// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "capture.h"
#include "config.h"
#include "net.h"
#include "server_ctrl_socket.h"
#include "internal.h"
#include "utils.h"

static volatile sig_atomic_t udbg_enh_stop_requested;

static void udbg_enh_server_request_stop(void)
{
	udbg_enh_stop_requested = 1;
}

static void udbg_enh_server_clear_stop(void)
{
	udbg_enh_stop_requested = 0;
}

static int udbg_enh_server_should_stop(void)
{
	return udbg_enh_stop_requested != 0;
}

static const char *transport_name(udbg_enh_transport_t transport)
{
	switch (transport) {
	case UDBG_ENH_TRANSPORT_TCP:
		return "tcp";
	case UDBG_ENH_TRANSPORT_UDP:
		return "udp";
	case UDBG_ENH_TRANSPORT_UNDEFINED:
		return "undefined";
	default:
		return "unknown";
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [<options>]\n"
		"\n"
		"  Options:\n"
		"    -B                          Run as daemon\n"
		"    -c <config-file>            Config path (required)\n"
		"    -r <rules-file>             Capture filter/scramble rules file\n"
		"    -s <ctrl-socket>            Control socket path override\n"
		"    -f <pcapng-file>            Start capture immediately to this output file\n"
		"    -h                          Show this help\n",
		prog);
}

/*
 * udbg_enh_daemonize: Handles udbg_enh_daemonize operation.
 * @chdir_root: Input parameter.
 * @output: Returns function result status/value.
 */
static int udbg_enh_daemonize(int chdir_root)
{
	pid_t pid;
	int fd;
	struct sigaction sa_hup;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		_exit(0);

	if (setsid() < 0)
		return -1;

	memset(&sa_hup, 0, sizeof(sa_hup));
	sa_hup.sa_handler = SIG_IGN;
	sigemptyset(&sa_hup.sa_mask);
	if (sigaction(SIGHUP, &sa_hup, NULL) < 0)
		return -1;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		_exit(0);

	umask(0);

	if (chdir_root && chdir("/") < 0)
		return -1;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0)
		return -1;

	if (dup2(fd, STDIN_FILENO) < 0 ||
		dup2(fd, STDOUT_FILENO) < 0 ||
		dup2(fd, STDERR_FILENO) < 0) {
		close(fd);
		return -1;
	}

	if (fd > STDERR_FILENO)
		close(fd);

	return 0;
}

/*
 * signal_handler: Handles signal_handler operation.
 * @signum: Input parameter.
 * @output: No return value.
 */
static void signal_handler(int signum)
{
	udbg_enh_server_request_stop();
}

/*
 * install_signal_handlers: Handles install_signal_handlers operation.
 * @output: Returns function result status/value.
 */
static int install_signal_handlers(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGTERM, &sa, NULL) < 0)
		return -1;
	if (sigaction(SIGINT, &sa, NULL) < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGPIPE, &sa, NULL) < 0)
		return -1;

	return 0;
}

struct udbg_enh_udp_rx_item {
	unsigned char buf[UDBG_ENH_MAX_MSG_SIZE];
	ssize_t len;
	struct sockaddr_in src;
};

static void capture_if_enabled(const struct udbg_enh_config *cfg,
			       const struct udbg_enh_capture_rules *capture_rules,
			       struct udbg_enh_pcapng_context *pcapng_ctx,
			       const char *transport, uint32_t msg_type,
			       const void *packet, size_t packet_len);

/*
 * debug_msg_decode_header: Decode fixed-width header fields from wire bytes.
 * @buf: Input wire buffer containing at least a debug message header.
 * @msg: Output decoded debug message header fields.
 * @output: No return value.
 */
static void debug_msg_decode_header(const unsigned char *buf, struct debug_msg *msg)
{
	memset(msg, 0, sizeof(*msg));
	msg->handle = udbg_enh_get_u64_le(buf + DEBUG_MSG_OFF_HANDLE);
	msg->msg_type = udbg_enh_get_u32_le(buf + DEBUG_MSG_OFF_MSG_TYPE);
	msg->timestamp = udbg_enh_get_u64_le(buf + DEBUG_MSG_OFF_TIMESTAMP);
	msg->length = udbg_enh_get_u32_le(buf + DEBUG_MSG_OFF_LENGTH);
}

/*
 * debug_msg_decode_subscribe_req: Decode subscribe-request payload fields.
 * @buf: Input wire buffer containing header + subscribe request payload.
 * @buf_len: Total size of @buf in bytes.
 * @pinfo: Output process identity populated from payload.
 * @output: Returns 0 on success, -1 on invalid input size/arguments.
 */
static int debug_msg_decode_subscribe_req(const unsigned char *buf,
					  size_t buf_len,
					  struct udbg_enh_process_info *pinfo)
{
	const unsigned char *payload;
	const size_t pid_len = sizeof(uint32_t);
	const size_t uuid_len = sizeof(pinfo->uuid);
	const size_t app_id_len = sizeof(pinfo->app_id);
	uint32_t wire_pid;

	if (!buf || !pinfo || buf_len < DEBUG_MSG_HEADER_SIZE + DEBUG_MSG_SUBSCRIBE_REQ_SIZE)
		return -1;

	payload = buf + DEBUG_MSG_HEADER_SIZE;
	memset(pinfo, 0, sizeof(*pinfo));
	wire_pid = udbg_enh_get_u32_le(payload) & UDBG_ENH_WIRE_PID_MASK;
	pinfo->pid = (pid_t)(int32_t)wire_pid;
	memcpy(pinfo->uuid, payload + pid_len, uuid_len);
	memcpy(pinfo->app_id, payload + pid_len + uuid_len, app_id_len);
	return 0;
}

/*
 * debug_msg_encode_subscribe_resp: Encode a subscribe response into wire bytes.
 * @buf: Output buffer receiving encoded response.
 * @buf_len: Size of @buf in bytes.
 * @handle: Subscription handle to place in the response.
 * @status: Subscribe response status code.
 * @output: Returns encoded length on success, 0 on buffer/argument failure.
 */
static size_t debug_msg_encode_subscribe_resp(unsigned char *buf, size_t buf_len,
					      uint64_t handle, int32_t status)
{
	const size_t msg_len = DEBUG_MSG_HEADER_SIZE + DEBUG_MSG_SUBSCRIBE_RESP_SIZE;

	if (!buf || buf_len < msg_len)
		return 0;

	memset(buf, 0, msg_len);
	udbg_enh_put_u64_le(buf + DEBUG_MSG_OFF_HANDLE, handle);
	udbg_enh_put_u32_le(buf + DEBUG_MSG_OFF_MSG_TYPE, UDBG_SUBSCRIBE_RESP);
	udbg_enh_put_u64_le(buf + DEBUG_MSG_OFF_TIMESTAMP, 0);
	udbg_enh_put_u32_le(buf + DEBUG_MSG_OFF_LENGTH, (uint32_t)msg_len);
	udbg_enh_put_u32_le(buf + DEBUG_MSG_HEADER_SIZE, (uint32_t)status);
	return msg_len;
}

/*
 * calc_expected_msg_len: Compute full message length for 32-bit payload format.
 * @declared_payload_len: Payload length read from packet/body.
 * @expected_msg_len: Output total message length.
 * @output: Returns 0 on success, -1 on overflow/invalid output pointer.
 */
static int calc_expected_msg_len(uint32_t declared_payload_len,
				 size_t *expected_msg_len)
{
	const size_t base_len = DEBUG_MSG_HEADER_SIZE + sizeof(uint32_t);

	if (!expected_msg_len) {
		errno = EINVAL;
		return -1;
	}

#if SIZE_MAX <= UINT32_MAX
	if ((size_t)declared_payload_len > SIZE_MAX - base_len) {
		errno = EOVERFLOW;
		return -1;
	}
#endif

	*expected_msg_len = base_len + (size_t)declared_payload_len;
	return 0;
}

/*
 * init_subscribe_resp_msg: Populate in-memory subscribe response fields.
 * @resp: Output debug message structure to initialize.
 * @handle: Subscription handle to include in the response.
 * @status: Subscribe response status code.
 * @output: No return value.
 */
static void init_subscribe_resp_msg(struct debug_msg *resp, uint64_t handle, int32_t status)
{
	if (!resp)
		return;

	memset(resp, 0, sizeof(*resp));
	resp->handle = handle;
	resp->msg_type = UDBG_SUBSCRIBE_RESP;
	resp->timestamp = 0;
	resp->length = (uint32_t)(DEBUG_MSG_HEADER_SIZE + DEBUG_MSG_SUBSCRIBE_RESP_SIZE);
	resp->u.subscribe_resp.status = status;
}

/*
 * capture_if_enabled: Conditionally capture packets to pcapng output.
 * @cfg: Server configuration controlling capture enable/path.
 * @capture_rules: Optional capture rules for filter/scramble behavior.
 * @pcapng_ctx: Open pcapng context used for packet write operations.
 * @transport: Transport label for logging context.
 * @msg_type: Message type associated with the packet.
 * @packet: Input packet bytes to capture.
 * @packet_len: Size of @packet in bytes.
 * @output: No return value.
 */
static void capture_if_enabled(const struct udbg_enh_config *cfg,
			       const struct udbg_enh_capture_rules *capture_rules,
			       struct udbg_enh_pcapng_context *pcapng_ctx,
			       const char *transport, uint32_t msg_type,
			       const void *packet, size_t packet_len)
{
	const void *capture_packet = packet;
	size_t capture_len = packet_len;
	unsigned char *scrambled_packet = NULL;

	if (!cfg || !pcapng_ctx || pcapng_ctx->open_status <= 0 || !packet ||
		packet_len == 0)
		return;
	if (capture_rules && capture_rules->enabled) {
		if (!udbg_enh_capture_rules_pass(capture_rules, packet, packet_len))
			return;
		if (capture_rules->scramble_count > 0) {
			scrambled_packet = (unsigned char *)malloc(packet_len);
			if (!scrambled_packet) {
				UDBG_ENH_LOG("%s capture scramble allocation failed len=%zu",
							   transport ? transport : "unknown",
							   packet_len);
				return;
			}
			memcpy(scrambled_packet, packet, packet_len);
			udbg_enh_capture_rules_scramble(capture_rules, scrambled_packet, packet_len);
			capture_packet = scrambled_packet;
			capture_len = packet_len;
		}
	}
	if (udbg_enh_pcapng_write(pcapng_ctx, capture_packet, capture_len) < 0) {
		UDBG_ENH_LOG("%s pcapng write failed msg_type=0x%08x len=%zu",
					   transport ? transport : "unknown",
					   msg_type, capture_len);
	}
	free(scrambled_packet);
}

/*
 * process_subscribe_request: Validate and process UDP subscribe request.
 * @fd: UDP socket used to send subscribe responses.
 * @subs: Subscription table to update/allocate client state.
 * @msg: Decoded header of incoming subscribe packet.
 * @buf: Raw received packet bytes.
 * @n: Received packet length in bytes.
 * @src: Source endpoint of incoming subscribe request.
 * @output: Returns 1 on success, 0 when request is rejected/invalid.
 */
static int process_subscribe_request(int fd,
				     struct udbg_enh_subscription_table *subs,
				     const struct debug_msg *msg,
				     const unsigned char *buf, ssize_t n,
				     const struct sockaddr_in *src)
{
	struct udbg_enh_process_info pinfo;
	struct udbg_enh_client_info *ci;
	struct debug_msg resp_msg;
	unsigned char resp_buf[DEBUG_MSG_HEADER_SIZE + DEBUG_MSG_SUBSCRIBE_RESP_SIZE];
	uint64_t now_us;
	size_t write_index = 0;
	int is_new_subscription = 0;
	size_t resp_len;

	if ((size_t)n < DEBUG_MSG_HEADER_SIZE + DEBUG_MSG_SUBSCRIBE_REQ_SIZE) {
		char src_ep[64];
		udbg_enh_format_sockaddr(src, src_ep, sizeof(src_ep));
		UDBG_ENH_LOG(
			"udp subscribe rejected src=%s reason=payload-too-small bytes=%zd need>=%zu",
			src_ep,
			n,
			DEBUG_MSG_HEADER_SIZE + DEBUG_MSG_SUBSCRIBE_REQ_SIZE);
		return 0;
	}
	if (msg->handle != 0) {
		char src_ep[64];
		udbg_enh_format_sockaddr(src, src_ep, sizeof(src_ep));
		UDBG_ENH_LOG(
			"udp subscribe rejected src=%s reason=invalid-handle handle=%llu",
			src_ep,
			(unsigned long long)msg->handle);
		return 0;
	}

	if (debug_msg_decode_subscribe_req(buf, (size_t)n, &pinfo) < 0)
		return 0;

	now_us = monotonic_now_us();
	ci = subs_find_by_process_info(subs, &pinfo, 1);
	if (!ci) {
		is_new_subscription = 1;
		if (!subs->table_full) {
			write_index = subs->head;
			ci = &subs->clients[write_index];
		} else {
			ci = subs_find_next_stale_from_head(subs, &write_index);
			if (!ci) {
				char src_ep[64];
				udbg_enh_format_sockaddr(src, src_ep, sizeof(src_ep));
				UDBG_ENH_LOG(
					"udp subscribe rejected src=%s reason=subscription-table-full-no-stale",
					src_ep);
				return 0;
			}
		}
	}
	if (ci->fd >= 0)
		close(ci->fd);

	ci->fd = -1;
	ci->pid_info = pinfo;
	ci->addr = *src;
	free(ci->nlctrl_nl80211_msg);
	ci->nlctrl_nl80211_msg = NULL;
	if (is_new_subscription)
		ci->handle = 0;
	subs_touch_client(ci, now_us, 1);

	if (ci->handle == 0 || subs_handle_exists(subs, ci->handle, ci))
		ci->handle = subs_generate_handle(subs, &pinfo, ci);
	if (is_new_subscription)
		subs_advance_head(subs, write_index);

	init_subscribe_resp_msg(&resp_msg, ci->handle, 1);
	resp_len = debug_msg_encode_subscribe_resp(
		resp_buf,
		sizeof(resp_buf),
		resp_msg.handle,
		resp_msg.u.subscribe_resp.status);
	if (resp_len == 0)
		return 1;

	{
		ssize_t sent = sendto(fd, resp_buf, resp_len, 0,
				      (struct sockaddr *)src,
				      sizeof(*src));
		char src_ep[64];
		udbg_enh_format_sockaddr(src, src_ep, sizeof(src_ep));
		if (sent == (ssize_t)resp_len) {
			UDBG_ENH_LOG(
				"udp subscribe success src=%s handle=%llu resp_status=%d msg_type=0x%08x",
				src_ep,
				(unsigned long long)resp_msg.handle,
				resp_msg.u.subscribe_resp.status,
				resp_msg.msg_type);
		} else if (sent < 0) {
			UDBG_ENH_LOG(
				"udp subscribe response-failed src=%s handle=%llu msg_type=0x%08x errno=%d(%s)",
				src_ep,
				(unsigned long long)resp_msg.handle,
				resp_msg.msg_type,
				errno,
				strerror(errno));
		} else {
			UDBG_ENH_LOG(
				"udp subscribe response-short-write src=%s handle=%llu msg_type=0x%08x sent=%zd need=%zu",
				src_ep,
				(unsigned long long)resp_msg.handle,
				resp_msg.msg_type,
				sent,
				resp_len);
		}
	}
	return 1;
}

/*
 * process_log_message: Validate UDP data message source and cache
 * nlctrl_nl80211 payload for flush snapshots.
 * @subs: Subscription table used for handle/source checks.
 * @msg: Decoded incoming message header.
 * @buf: Full received wire packet.
 * @n: Received packet length in bytes.
 * @src: Source endpoint for request validation.
 * @output: Returns 1 when message is accepted, else 0.
 */
static int process_log_message(struct udbg_enh_subscription_table *subs,
			       const struct debug_msg *msg,
			       const unsigned char *buf, ssize_t n,
			       const struct sockaddr_in *src)
{
	uint32_t msg_type = msg->msg_type;
	struct udbg_enh_client_info *ci;
	uint64_t now_us;
	char src_ep[64];

	udbg_enh_format_sockaddr(src, src_ep, sizeof(src_ep));
	if (msg->handle == 0) {
		UDBG_ENH_LOG(
			"udp drop data src=%s handle=0 msg_type=0x%08x reason=invalid-handle",
			src_ep,
			(unsigned int)msg_type);
		return 0;
	}

	ci = subs_find_by_handle_any(subs, msg->handle);
	if (!ci) {
		UDBG_ENH_LOG(
			"udp drop data src=%s handle=%llu msg_type=0x%08x reason=unknown-handle",
			src_ep,
			(unsigned long long)msg->handle,
			(unsigned int)msg_type);
		return 0;
	}
	if (!subs_udp_src_matches(ci, src)) {
		char src_ep2[64];
		char expected_ep[64];
		udbg_enh_format_sockaddr(src, src_ep2, sizeof(src_ep2));
		udbg_enh_format_sockaddr(&ci->addr, expected_ep, sizeof(expected_ep));
		UDBG_ENH_LOG(
			"udp drop data src=%s handle=%llu msg_type=0x%08x reason=source-mismatch expected_src=%s expected_port=%u",
			src_ep2,
			(unsigned long long)msg->handle,
			(unsigned int)msg_type,
			expected_ep,
			(unsigned int)ntohs(ci->addr.sin_port));
		return 0;
	}

	if (msg->msg_type == UDBG_NLCTRL_NL80211) {
		uint32_t declared_payload_len;
		size_t expected_msg_len;
		struct debug_msg *cached_msg;

		if (n < (ssize_t)(DEBUG_MSG_HEADER_SIZE + sizeof(uint32_t))) {
			UDBG_ENH_LOG(
				"udp drop data src=%s handle=%llu msg_type=0x%08x reason=nlctrl-short-payload",
				src_ep,
				(unsigned long long)msg->handle,
				(unsigned int)msg_type);
			return 0;
			}

			declared_payload_len = udbg_enh_get_u32_le(buf + DEBUG_MSG_HEADER_SIZE);
			if (calc_expected_msg_len(declared_payload_len,
						  &expected_msg_len) < 0) {
				UDBG_ENH_LOG(
					"udp drop data src=%s handle=%llu msg_type=0x%08x reason=nlctrl-length-overflow payload_len=%u",
					src_ep,
				(unsigned long long)msg->handle,
				(unsigned int)msg_type,
				(unsigned int)declared_payload_len);
				return 0;
			}

			if ((size_t)msg->length != expected_msg_len) {
				UDBG_ENH_LOG(
					"udp drop data src=%s handle=%llu msg_type=0x%08x reason=nlctrl-length-mismatch frame_len=%u expected_len=%zu",
				src_ep,
				(unsigned long long)msg->handle,
				(unsigned int)msg_type,
				(unsigned int)msg->length,
				expected_msg_len);
			return 0;
		}

		cached_msg = (struct debug_msg *)malloc((size_t)msg->length);
		if (!cached_msg) {
			UDBG_ENH_LOG(
				"udp nlctrl cache alloc failed src=%s handle=%llu msg_type=0x%08x len=%u",
				src_ep,
				(unsigned long long)msg->handle,
				(unsigned int)msg_type,
				(unsigned int)msg->length);
		} else {
			memcpy(cached_msg, buf, (size_t)msg->length);
			free(ci->nlctrl_nl80211_msg);
			ci->nlctrl_nl80211_msg = cached_msg;
		}
	}

	now_us = monotonic_now_us();
	subs_touch_client(ci, now_us, 1);
	return 1;
}

/*
 * process_udp_packet: Decode one UDP packet and dispatch by message type.
 * @cfg: Server configuration for capture and behavior settings.
 * @fd: UDP socket descriptor used for responses.
 * @subs: Subscription table containing client state.
 * @ring: Packet ring receiving accepted packets.
 * @capture_rules: Optional packet filter/scramble rules for capture.
 * @pcapng_ctx: Capture context used for optional packet logging.
 * @buf: Raw received packet bytes.
 * @n: Received packet length in bytes.
 * @src: Source endpoint of received packet.
 * @output: No return value.
 */
static void process_udp_packet(const struct udbg_enh_config *cfg, int fd,
				struct udbg_enh_subscription_table *subs,
				struct udbg_enh_ring_buffer *ring,
				const struct udbg_enh_capture_rules *capture_rules,
				struct udbg_enh_pcapng_context *pcapng_ctx,
				const unsigned char *buf, ssize_t n,
				const struct sockaddr_in *src)
{
	struct debug_msg msg;
	int accepted = 0;

	if (!cfg || !subs || !ring || !buf || !src)
		return;

	if ((size_t)n < DEBUG_MSG_HEADER_SIZE) {
		char src_ep[64];
		udbg_enh_format_sockaddr(src, src_ep, sizeof(src_ep));
		UDBG_ENH_LOG("udp drop short-packet src=%s bytes=%zd need>=%zu",
					   src_ep, n, DEBUG_MSG_HEADER_SIZE);
		return;
	}

	debug_msg_decode_header(buf, &msg);
	{
		char src_ep[64];
		udbg_enh_format_sockaddr(src, src_ep, sizeof(src_ep));
		UDBG_ENH_LOG("udp recv src=%s bytes=%zd msg_type=0x%08x handle=%llu length=%u",
					   src_ep,
					   n,
					   msg.msg_type,
					   (unsigned long long)msg.handle,
					   msg.length);
	}
	if (msg.length != (uint32_t)n) {
		char src_ep[64];
		udbg_enh_format_sockaddr(src, src_ep, sizeof(src_ep));
		UDBG_ENH_LOG(
			"udp drop length-mismatch src=%s header_length=%u received_bytes=%zd",
			src_ep,
			msg.length,
			n);
		return;
	}
	switch (msg.msg_type) {
	case UDBG_SUBSCRIBE_REQ:
		accepted = process_subscribe_request(fd, subs, &msg, buf, n, src);
		break;
	case UDBG_NL_TX:
	case UDBG_NL_RX:
	case UDBG_NLCTRL_NL80211:
	case UDBG_LOG:
		accepted = process_log_message(subs, &msg, buf, n, src);
		break;
	default:
		if (UDBG_ENH_MSG_BASE(msg.msg_type) == UDBG_ENH_CTRL_CMD_BASE) {
			char src_ep[64];
			udbg_enh_format_sockaddr(src, src_ep, sizeof(src_ep));
			UDBG_ENH_LOG(
				"udp drop control src=%s handle=%llu msg_type=0x%08x reason=unsupported-control-type",
				src_ep,
				(unsigned long long)msg.handle,
				(unsigned int)msg.msg_type);
		} else if (UDBG_ENH_MSG_BASE(msg.msg_type) == UDBG_ENH_DATA_CMD_BASE) {
			accepted = process_log_message(subs, &msg, buf, n, src);
		} else {
			char src_ep[64];
			udbg_enh_format_sockaddr(src, src_ep, sizeof(src_ep));
			UDBG_ENH_LOG(
				"udp drop unknown src=%s handle=%llu msg_type=0x%08x reason=unsupported-message-base",
				src_ep,
				(unsigned long long)msg.handle,
				(unsigned int)msg.msg_type);
		}
		break;
	}
	if (accepted)
		capture_if_enabled(cfg, capture_rules, pcapng_ctx, "udp", msg.msg_type, buf,
						   (size_t)n);
	if (accepted &&
		udbg_enh_ring_push(ring, msg.msg_type, msg.handle, buf, (size_t)n) < 0) {
		UDBG_ENH_LOG("udp ring write failed msg_type=0x%08x handle=%llu len=%zd",
				msg.msg_type,
				(unsigned long long)msg.handle,
				n);
	}
}

/*
 * write_flush_packet: Write one packet to flush capture with optional rules.
 * @flush_ctx: Open flush capture context.
 * @capture_rules: Optional capture rules applied to FLUSH output.
 * @packet: Raw packet bytes to write.
 * @packet_len: Packet size in bytes.
 * @output: Returns 1 when packet is written, 0 when filtered, -1 on error.
 */
static int write_flush_packet(struct udbg_enh_pcapng_context *flush_ctx,
			      const struct udbg_enh_capture_rules *capture_rules,
			      const void *packet, size_t packet_len)
{
	const void *capture_packet = packet;
	size_t capture_len = packet_len;
	unsigned char *scrambled_packet = NULL;
	int rc = -1;

	if (!flush_ctx || !packet || packet_len == 0) {
		errno = EINVAL;
		return -1;
	}

	if (capture_rules && capture_rules->enabled) {
		if (!udbg_enh_capture_rules_pass(capture_rules, packet, packet_len))
			return 0;
		if (capture_rules->scramble_count > 0) {
			scrambled_packet = (unsigned char *)malloc(packet_len);
			if (!scrambled_packet) {
				errno = ENOMEM;
				return -1;
			}
			memcpy(scrambled_packet, packet, packet_len);
			udbg_enh_capture_rules_scramble(capture_rules, scrambled_packet, packet_len);
			capture_packet = scrambled_packet;
			capture_len = packet_len;
		}
	}

	if (udbg_enh_pcapng_write(flush_ctx, capture_packet, capture_len) < 0)
		goto out;

	rc = 1;

out:
	free(scrambled_packet);
	return rc;
}

/*
 * subs_used_count_for_flush: Return number of subscription slots to scan.
 * @subs: Subscription table.
 * @output: Number of client slots currently in-use.
 */
static size_t subs_used_count_for_flush(const struct udbg_enh_subscription_table *subs)
{
	if (!subs)
		return 0;
	if (subs->table_full || subs->nclients >= subs->capacity)
		return subs->capacity;
	return subs->nclients;
}

/*
 * notify_and_drop_stale_clients: Mark timed-out clients stale.
 * @subs: Subscription table containing client state.
 * @now_us: Current monotonic timestamp in microseconds.
 * @stale_timeout_us: Timeout threshold in microseconds.
 * @output: No return value.
 */
static void notify_and_drop_stale_clients(struct udbg_enh_subscription_table *subs,
					  uint64_t now_us,
					  uint64_t stale_timeout_us)
{
	size_t used;
	size_t i;

	if (!subs || !subs->clients || stale_timeout_us == 0 || now_us == 0)
		return;

	used = subs_used_count_for_flush(subs);
	for (i = 0; i < used; ++i) {
		struct udbg_enh_client_info *ci = &subs->clients[i];

		if (!ci->active || ci->last_seen_us == 0)
			continue;
		if (now_us > ci->last_seen_us &&
		    now_us - ci->last_seen_us >= stale_timeout_us)
			ci->active = 0;
	}
}

/*
 * write_active_clients_nlctrl: Write cached nlctrl_nl80211 of active clients.
 * @flush_ctx: Open flush capture context.
 * @subs: Subscription table containing client states.
 * @capture_rules: Optional capture rules applied to FLUSH output.
 * @written_packets: Optional number of packets written.
 * @output: Returns 0 on success, -1 on write/validation failure.
 */
static int write_active_clients_nlctrl(struct udbg_enh_pcapng_context *flush_ctx,
				       const struct udbg_enh_subscription_table *subs,
				       const struct udbg_enh_capture_rules *capture_rules,
				       size_t *written_packets)
{
	size_t used;
	size_t i;

	if (written_packets)
		*written_packets = 0;

	if (!flush_ctx || !subs || !subs->clients || subs->capacity == 0) {
		errno = EINVAL;
		return -1;
	}

	used = subs_used_count_for_flush(subs);
	for (i = 0; i < used; ++i) {
		const struct udbg_enh_client_info *ci = &subs->clients[i];
		const unsigned char *nlctrl_packet;
		uint32_t packet_msg_type;
		uint32_t packet_len_u32;
		uint32_t declared_payload_len;
		size_t packet_len;
		size_t expected_msg_len;
		int write_rc;

		if (!ci->active || ci->handle == 0)
			continue;
		if (!ci->nlctrl_nl80211_msg)
			continue;

		nlctrl_packet = (const unsigned char *)ci->nlctrl_nl80211_msg;
		packet_msg_type = udbg_enh_get_u32_le(nlctrl_packet + DEBUG_MSG_OFF_MSG_TYPE);
		if (packet_msg_type != UDBG_NLCTRL_NL80211)
			continue;

		packet_len_u32 = udbg_enh_get_u32_le(nlctrl_packet + DEBUG_MSG_OFF_LENGTH);
		packet_len = (size_t)packet_len_u32;
			if (packet_len < DEBUG_MSG_HEADER_SIZE + sizeof(uint32_t))
				continue;

			declared_payload_len = udbg_enh_get_u32_le(nlctrl_packet + DEBUG_MSG_HEADER_SIZE);
			if (calc_expected_msg_len(declared_payload_len,
						  &expected_msg_len) < 0)
				continue;

			if (expected_msg_len != packet_len)
				continue;

		write_rc = write_flush_packet(flush_ctx,
					      capture_rules,
					      nlctrl_packet,
					      packet_len);
		if (write_rc < 0)
			return -1;
		if (write_rc > 0 && written_packets)
			(*written_packets)++;
	}
	return 0;
}

/*
 * dump_ring_snapshot_to_file: Write flush snapshot into a new pcapng file.
 * @ring: Ring buffer to snapshot.
 * @subs: Subscription table containing active clients.
 * @file_name: Destination path for pcapng output.
 * @capture_rules: Optional capture rules applied to FLUSH output.
 * @written_nlctrl_packets: Optional number of active-client nlctrl packets written.
 * @written_ring_packets: Optional number of ring packets written.
 * @output: Returns 0 on success, -1 on validation/write/open failure.
 */
static int dump_ring_snapshot_to_file(const struct udbg_enh_ring_buffer *ring,
				      const struct udbg_enh_subscription_table *subs,
				      const char *file_name,
				      const struct udbg_enh_capture_rules *capture_rules,
				      size_t *written_nlctrl_packets,
				      size_t *written_ring_packets)
{
	struct udbg_enh_pcapng_context flush_ctx;
	size_t snapshot_count;
	size_t start;
	size_t i;
	int rc = -1;

	if (written_nlctrl_packets)
		*written_nlctrl_packets = 0;
	if (written_ring_packets)
		*written_ring_packets = 0;

	if (!ring || !ring->entries || ring->capacity == 0 ||
	    !subs || !subs->clients || subs->capacity == 0 ||
	    !file_name || file_name[0] == '\0') {
		errno = EINVAL;
		return -1;
	}
	if (ring->count > ring->capacity) {
		errno = EINVAL;
		return -1;
	}

	snapshot_count = ring->count;
	start = (ring->write_index + ring->capacity - snapshot_count) % ring->capacity;

	udbg_enh_pcapng_init(&flush_ctx);
	if (udbg_enh_pcapng_open(&flush_ctx, file_name) < 0)
		return -1;

	if (write_active_clients_nlctrl(&flush_ctx,
					subs,
					capture_rules,
					written_nlctrl_packets) < 0)
		goto out;

	for (i = 0; i < snapshot_count; ++i) {
		const struct udbg_enh_ring_entry *entry;
		size_t idx = (start + i) % ring->capacity;
		int write_rc;

		entry = &ring->entries[idx];
		if (!entry->packet_data || entry->packet_len == 0)
			continue;
		write_rc = write_flush_packet(&flush_ctx,
					      capture_rules,
					      entry->packet_data,
					      entry->packet_len);
		if (write_rc < 0)
			goto out;
		if (write_rc > 0 && written_ring_packets)
			(*written_ring_packets)++;
	}

	if (udbg_enh_pcapng_flush(&flush_ctx) < 0)
		goto out;

	rc = 0;

out:
	if (udbg_enh_pcapng_close(&flush_ctx) < 0 && rc == 0)
		rc = -1;
	return rc;
}

/*
 * run_udp_server: Run UDP server loop and process incoming packets.
 * @cfg: Server configuration for bind/capture/batching behavior.
 * @capture_rules: Optional capture rules loaded from rules file.
 * @control_socket_path: Optional control socket path override.
 * @startup_capture_path: Optional startup capture output path from -f.
 * @output: No return value.
 */
static void run_udp_server(const struct udbg_enh_config *cfg,
			   const struct udbg_enh_capture_rules *capture_rules,
			   const char *control_socket_path,
			   const char *startup_capture_path)
{
	int fd = -1;
	int udbg_enh_server_ctrl_fd = -1;
	int max_fd;
	int udbg_enh_server_ctrl_terminate_requested = 0;
	int udbg_enh_server_ctrl_flush_requested = 0;
	int udbg_enh_server_ctrl_start_requested = 0;
	int udbg_enh_server_ctrl_stop_requested = 0;
	char udbg_enh_server_ctrl_flush_file_name[PATH_MAX];
	char udbg_enh_server_ctrl_flush_rules_file_name[PATH_MAX];
	char udbg_enh_server_ctrl_start_file_name[PATH_MAX];
	char udbg_enh_server_ctrl_start_rules_file_name[PATH_MAX];
	struct sockaddr_un udbg_enh_server_ctrl_flush_peer;
	struct sockaddr_un udbg_enh_server_ctrl_start_peer;
	struct sockaddr_un udbg_enh_server_ctrl_stop_peer;
	socklen_t udbg_enh_server_ctrl_flush_peer_len = 0;
	socklen_t udbg_enh_server_ctrl_start_peer_len = 0;
	socklen_t udbg_enh_server_ctrl_stop_peer_len = 0;
	const char *ctrl_socket_path;
	const struct udbg_enh_capture_rules *active_capture_rules = NULL;
	struct udbg_enh_capture_rules runtime_capture_rules = { 0 };
	int runtime_capture_rules_active = 0;
	struct udbg_enh_server_ctrl_socket udbg_enh_server_ctrl_ctx;
	struct sockaddr_in addr;
	struct udbg_enh_subscription_table subs;
	struct udbg_enh_pcapng_context pcapng_ctx;
	struct udbg_enh_ring_buffer ring = { 0 };
	struct udbg_enh_udp_rx_item *batch_items = NULL;
	uint32_t requested_batch_size;
	uint32_t batch_size;
	uint32_t batch_budget_us;
	uint64_t liveness_interval_us;
	uint64_t stale_timeout_us;
	uint64_t next_liveness_sweep_us = 0;
	int batch_enable;

	memset(&udbg_enh_server_ctrl_ctx, 0, sizeof(udbg_enh_server_ctrl_ctx));
	udbg_enh_server_ctrl_ctx.fd = -1;
	udbg_enh_server_ctrl_flush_file_name[0] = '\0';
	udbg_enh_server_ctrl_flush_rules_file_name[0] = '\0';
	udbg_enh_server_ctrl_start_file_name[0] = '\0';
	udbg_enh_server_ctrl_start_rules_file_name[0] = '\0';
	memset(&udbg_enh_server_ctrl_flush_peer, 0,
	       sizeof(udbg_enh_server_ctrl_flush_peer));
	memset(&udbg_enh_server_ctrl_start_peer, 0,
	       sizeof(udbg_enh_server_ctrl_start_peer));
	memset(&udbg_enh_server_ctrl_stop_peer, 0,
	       sizeof(udbg_enh_server_ctrl_stop_peer));

	if (subs_init(&subs, cfg) < 0) {
		perror("calloc");
		return;
	}
	udbg_enh_pcapng_init(&pcapng_ctx);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		subs_deinit(&subs);
		return;
	}

	if (udbg_enh_set_nonblocking(fd) < 0) {
		perror("fcntl");
		close(fd);
		subs_deinit(&subs);
		return;
	}

	if (set_socket_buffers(fd, 256 * 1024) < 0) {
		perror("setsockopt");
		/*
		 * Continue even if socket buffer tuning fails; server can still run.
		 */
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(cfg->server_port);
	if (inet_pton(AF_INET, cfg->server_ip, &addr.sin_addr) != 1) {
		UDBG_ENH_LOG("invalid bind ip='%s' (expected IPv4 address)",
			     cfg->server_ip);
		close(fd);
		subs_deinit(&subs);
		return;
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(fd);
		subs_deinit(&subs);
		return;
	}

	ctrl_socket_path = control_socket_path && control_socket_path[0] != '\0' ?
		control_socket_path : DEFAULT_CONTROL_SOCKET_PATH;
	if (udbg_enh_server_ctrl_socket_open(&udbg_enh_server_ctrl_ctx,
					     ctrl_socket_path) < 0) {
		perror("ctrl_socket_open");
		close(fd);
		subs_deinit(&subs);
		return;
	}
	udbg_enh_server_ctrl_fd = udbg_enh_server_ctrl_socket_get_fd(
		&udbg_enh_server_ctrl_ctx);
	if (udbg_enh_server_ctrl_fd < 0) {
		udbg_enh_server_ctrl_socket_close(&udbg_enh_server_ctrl_ctx);
		close(fd);
		subs_deinit(&subs);
		return;
	}
	max_fd = (fd > udbg_enh_server_ctrl_fd) ? fd : udbg_enh_server_ctrl_fd;

	requested_batch_size = cfg->udp_batch_size;
	batch_size = clamp_udp_batch_size(requested_batch_size);
	batch_budget_us = cfg->udp_batch_budget_us;
	liveness_interval_us = (uint64_t)cfg->liveness_check_interval_ms * 1000ull;
	stale_timeout_us = (uint64_t)cfg->stale_timeout_ms * 1000ull;
	batch_enable = cfg->udp_batch_enable ? 1 : 0;
	if (!batch_enable) {
		batch_size = 1;
		batch_budget_us = 0;
	}

	batch_items = (struct udbg_enh_udp_rx_item *)calloc(batch_size,
															   sizeof(*batch_items));
	if (!batch_items) {
		perror("calloc");
		if (batch_size != 1) {
			batch_size = 1;
			batch_budget_us = 0;
			batch_items = (struct udbg_enh_udp_rx_item *)calloc(
				batch_size, sizeof(*batch_items));
		}
		if (!batch_items) {
			udbg_enh_server_ctrl_socket_close(&udbg_enh_server_ctrl_ctx);
			close(fd);
			subs_deinit(&subs);
			return;
		}
		UDBG_ENH_LOG("udp batch allocation fallback size=1");
	}
	if (udbg_enh_ring_init(&ring, (size_t)cfg->server_max_log_entries) < 0) {
		UDBG_ENH_LOG("udp ring init failed entries=%u",
			(unsigned int)cfg->server_max_log_entries);
		free(batch_items);
		udbg_enh_server_ctrl_socket_close(&udbg_enh_server_ctrl_ctx);
		close(fd);
		subs_deinit(&subs);
		return;
	}

	UDBG_ENH_LOG("udp listen ip=%s port=%u", cfg->server_ip, (unsigned int)cfg->server_port);
	UDBG_ENH_LOG("ctrl listen path=%s", ctrl_socket_path);
	UDBG_ENH_LOG(
		"udp batch config enabled=%d requested_size=%u effective_size=%u budget_us=%u",
		batch_enable,
		(unsigned int)requested_batch_size,
		(unsigned int)batch_size,
		(unsigned int)batch_budget_us);
	UDBG_ENH_LOG("udp liveness config check_interval_ms=%u stale_timeout_ms=%u",
		     (unsigned int)cfg->liveness_check_interval_ms,
		     (unsigned int)cfg->stale_timeout_ms);
	if (startup_capture_path && startup_capture_path[0] != '\0') {
		if (udbg_enh_pcapng_open(&pcapng_ctx, startup_capture_path) == 0) {
			active_capture_rules =
				(capture_rules && capture_rules->enabled) ? capture_rules : NULL;
			UDBG_ENH_LOG("udp capture enabled pcapng=%s", udbg_enh_pcapng_path(&pcapng_ctx));
			if (active_capture_rules) {
				UDBG_ENH_LOG(
					"udp capture rules file=%s total=%zu filter=%zu filter_not=%zu scramble=%zu",
					active_capture_rules->path[0] ? active_capture_rules->path : "unknown",
					active_capture_rules->count,
					active_capture_rules->filter_count,
					active_capture_rules->filter_not_count,
					active_capture_rules->scramble_count);
			} else {
				UDBG_ENH_LOG(
					"udp capture rules disabled: no -r provided (no filter/scramble)");
			}
		} else {
			UDBG_ENH_LOG("udp capture open failed pcapng_path=%s",
					   startup_capture_path);
		}
	} else {
		UDBG_ENH_LOG("udp startup capture disabled: no -f provided");
	}

	while (!udbg_enh_server_should_stop()) {
		fd_set rfds;
		struct timeval tv;
		size_t batch_count = 0;
		size_t i;
		uint64_t batch_start_us = 0;
		uint64_t now_us = monotonic_now_us();

		if (now_us > 0 && liveness_interval_us > 0 &&
		    (next_liveness_sweep_us == 0 || now_us >= next_liveness_sweep_us)) {
			notify_and_drop_stale_clients(&subs, now_us, stale_timeout_us);
			next_liveness_sweep_us = now_us + liveness_interval_us;
		}

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		FD_SET(udbg_enh_server_ctrl_fd, &rfds);
		tv.tv_sec = 0;
		/*
		 * 10ms timeout keeps shutdown responsive without busy polling.
		 */
		tv.tv_usec = 10000;

		if (select(max_fd + 1, &rfds, NULL, NULL, &tv) < 0) {
			if (errno == EINTR)
				continue;
			perror("select");
			goto udp_done;
		}

		if (FD_ISSET(udbg_enh_server_ctrl_fd, &rfds)) {
			udbg_enh_server_ctrl_terminate_requested = 0;
			udbg_enh_server_ctrl_flush_requested = 0;
			udbg_enh_server_ctrl_start_requested = 0;
			udbg_enh_server_ctrl_stop_requested = 0;
			if (udbg_enh_server_ctrl_socket_handle_one(
				    &udbg_enh_server_ctrl_ctx,
				    &udbg_enh_server_ctrl_terminate_requested,
				    &udbg_enh_server_ctrl_flush_requested,
				    udbg_enh_server_ctrl_flush_file_name,
				    sizeof(udbg_enh_server_ctrl_flush_file_name),
				    udbg_enh_server_ctrl_flush_rules_file_name,
				    sizeof(udbg_enh_server_ctrl_flush_rules_file_name),
				    &udbg_enh_server_ctrl_flush_peer,
				    &udbg_enh_server_ctrl_flush_peer_len,
				    &udbg_enh_server_ctrl_start_requested,
				    udbg_enh_server_ctrl_start_file_name,
				    sizeof(udbg_enh_server_ctrl_start_file_name),
				    udbg_enh_server_ctrl_start_rules_file_name,
				    sizeof(udbg_enh_server_ctrl_start_rules_file_name),
				    &udbg_enh_server_ctrl_start_peer,
				    &udbg_enh_server_ctrl_start_peer_len,
				    &udbg_enh_server_ctrl_stop_requested,
				    &udbg_enh_server_ctrl_stop_peer,
				    &udbg_enh_server_ctrl_stop_peer_len) < 0) {
				perror("ctrl_socket_handle_one");
				goto udp_done;
			}
			if (udbg_enh_server_ctrl_terminate_requested) {
				udbg_enh_server_request_stop();
				continue;
			}
			if (udbg_enh_server_ctrl_flush_requested) {
				struct udbg_enh_capture_rules flush_capture_rules = { 0 };
				const struct udbg_enh_capture_rules *flush_capture_rules_ptr = NULL;
				char flush_rules_err[192];
				size_t written_nlctrl_packets = 0;
				size_t written_ring_packets = 0;
				int flush_rc = 0;
				int flush_rules_load_failed = 0;
				const char *reply;

				if (udbg_enh_server_ctrl_flush_rules_file_name[0] != '\0') {
					if (udbg_enh_capture_rules_load(
						    &flush_capture_rules,
						    udbg_enh_server_ctrl_flush_rules_file_name,
						    flush_rules_err,
						    sizeof(flush_rules_err)) < 0) {
						UDBG_ENH_LOG(
							"ctrl flush failed path=%s rules=%s reason=rules-load-failed detail=%s",
							udbg_enh_server_ctrl_flush_file_name,
							udbg_enh_server_ctrl_flush_rules_file_name,
							flush_rules_err[0] ? flush_rules_err : "unknown error");
						flush_rc = -1;
						flush_rules_load_failed = 1;
					} else {
						flush_capture_rules_ptr = &flush_capture_rules;
					}
				}
				if (flush_rc == 0) {
					flush_rc = dump_ring_snapshot_to_file(
						&ring,
						&subs,
						udbg_enh_server_ctrl_flush_file_name,
						flush_capture_rules_ptr,
						&written_nlctrl_packets,
						&written_ring_packets);
				}
				reply = flush_rc == 0 ? "OK\n" : "FAIL\n";

				if (flush_rc == 0) {
					UDBG_ENH_LOG(
						"ctrl flush success path=%s rules=%s packets=%zu nlctrl_packets=%zu ring_packets=%zu",
						udbg_enh_server_ctrl_flush_file_name,
						udbg_enh_server_ctrl_flush_rules_file_name[0] != '\0' ?
							udbg_enh_server_ctrl_flush_rules_file_name : "none",
						written_nlctrl_packets + written_ring_packets,
						written_nlctrl_packets,
						written_ring_packets);
				} else if (!flush_rules_load_failed) {
					UDBG_ENH_LOG(
						"ctrl flush failed path=%s rules=%s errno=%d(%s)",
						udbg_enh_server_ctrl_flush_file_name,
						udbg_enh_server_ctrl_flush_rules_file_name[0] != '\0' ?
							udbg_enh_server_ctrl_flush_rules_file_name : "none",
						errno,
						strerror(errno));
				}
				udbg_enh_capture_rules_deinit(&flush_capture_rules);

				if (udbg_enh_server_ctrl_socket_reply(
					    udbg_enh_server_ctrl_fd,
					    &udbg_enh_server_ctrl_flush_peer,
					    udbg_enh_server_ctrl_flush_peer_len,
					    reply) < 0) {
					perror("ctrl_socket_reply");
					goto udp_done;
				}
				continue;
			}
			if (udbg_enh_server_ctrl_start_requested) {
				struct udbg_enh_capture_rules start_capture_rules = { 0 };
				const struct udbg_enh_capture_rules *start_capture_rules_ptr = NULL;
				char start_rules_err[192];
				size_t written_nlctrl_packets = 0;
				const char *reply = "FAIL\n";

				if (pcapng_ctx.open_status > 0) {
					UDBG_ENH_LOG(
						"ctrl start failed path=%s rules=%s reason=capture-already-active current=%s",
						udbg_enh_server_ctrl_start_file_name,
						udbg_enh_server_ctrl_start_rules_file_name[0] != '\0' ?
							udbg_enh_server_ctrl_start_rules_file_name : "none",
						udbg_enh_pcapng_path(&pcapng_ctx));
					goto start_done;
				}

				if (udbg_enh_server_ctrl_start_rules_file_name[0] != '\0') {
					if (udbg_enh_capture_rules_load(
						    &start_capture_rules,
						    udbg_enh_server_ctrl_start_rules_file_name,
						    start_rules_err,
						    sizeof(start_rules_err)) < 0) {
						UDBG_ENH_LOG(
							"ctrl start failed path=%s rules=%s reason=rules-load-failed detail=%s",
							udbg_enh_server_ctrl_start_file_name,
							udbg_enh_server_ctrl_start_rules_file_name,
							start_rules_err[0] ? start_rules_err : "unknown error");
						goto start_done;
					}
					start_capture_rules_ptr = &start_capture_rules;
				}

				if (udbg_enh_pcapng_open(&pcapng_ctx,
							 udbg_enh_server_ctrl_start_file_name) < 0) {
					UDBG_ENH_LOG(
						"ctrl start failed path=%s rules=%s reason=open-failed errno=%d(%s)",
						udbg_enh_server_ctrl_start_file_name,
						udbg_enh_server_ctrl_start_rules_file_name[0] != '\0' ?
							udbg_enh_server_ctrl_start_rules_file_name : "none",
						errno,
						strerror(errno));
					goto start_done;
				}

				if (write_active_clients_nlctrl(&pcapng_ctx,
								&subs,
								start_capture_rules_ptr,
								&written_nlctrl_packets) < 0) {
					UDBG_ENH_LOG(
						"ctrl start failed path=%s rules=%s reason=nlctrl-dump-failed errno=%d(%s)",
						udbg_enh_server_ctrl_start_file_name,
						udbg_enh_server_ctrl_start_rules_file_name[0] != '\0' ?
							udbg_enh_server_ctrl_start_rules_file_name : "none",
						errno,
						strerror(errno));
					(void)udbg_enh_pcapng_close(&pcapng_ctx);
					goto start_done;
				}

				if (udbg_enh_pcapng_flush(&pcapng_ctx) < 0) {
					UDBG_ENH_LOG(
						"ctrl start failed path=%s rules=%s reason=flush-failed errno=%d(%s)",
						udbg_enh_server_ctrl_start_file_name,
						udbg_enh_server_ctrl_start_rules_file_name[0] != '\0' ?
							udbg_enh_server_ctrl_start_rules_file_name : "none",
						errno,
						strerror(errno));
					(void)udbg_enh_pcapng_close(&pcapng_ctx);
					goto start_done;
				}

				if (runtime_capture_rules_active) {
					udbg_enh_capture_rules_deinit(&runtime_capture_rules);
					runtime_capture_rules_active = 0;
				}
				if (start_capture_rules_ptr) {
					runtime_capture_rules = start_capture_rules;
					memset(&start_capture_rules, 0, sizeof(start_capture_rules));
					runtime_capture_rules_active = 1;
					active_capture_rules = &runtime_capture_rules;
				} else {
					active_capture_rules = NULL;
				}

				reply = "OK\n";
				UDBG_ENH_LOG(
					"ctrl start success path=%s rules=%s nlctrl_packets=%zu",
					udbg_enh_server_ctrl_start_file_name,
					udbg_enh_server_ctrl_start_rules_file_name[0] != '\0' ?
						udbg_enh_server_ctrl_start_rules_file_name : "none",
					written_nlctrl_packets);

start_done:
				udbg_enh_capture_rules_deinit(&start_capture_rules);
				if (udbg_enh_server_ctrl_socket_reply(
					    udbg_enh_server_ctrl_fd,
					    &udbg_enh_server_ctrl_start_peer,
					    udbg_enh_server_ctrl_start_peer_len,
					    reply) < 0) {
					perror("ctrl_socket_reply");
					goto udp_done;
				}
				continue;
			}
			if (udbg_enh_server_ctrl_stop_requested) {
				char stopped_path[PATH_MAX];
				const char *current_path = udbg_enh_pcapng_path(&pcapng_ctx);
				const char *reply = "FAIL\n";

				stopped_path[0] = '\0';
				if (current_path && current_path[0] != '\0') {
					(void)snprintf(stopped_path, sizeof(stopped_path), "%s",
						       current_path);
				}

				if (pcapng_ctx.open_status <= 0) {
					UDBG_ENH_LOG("ctrl stop failed reason=capture-not-active");
				} else if (udbg_enh_pcapng_close(&pcapng_ctx) < 0) {
					UDBG_ENH_LOG(
						"ctrl stop failed path=%s reason=close-failed errno=%d(%s)",
						stopped_path[0] != '\0' ? stopped_path : "unknown",
						errno,
						strerror(errno));
				} else {
					reply = "OK\n";
					UDBG_ENH_LOG("ctrl stop success path=%s",
						     stopped_path[0] != '\0' ? stopped_path : "unknown");
				}

				active_capture_rules = NULL;
				if (runtime_capture_rules_active) {
					udbg_enh_capture_rules_deinit(&runtime_capture_rules);
					runtime_capture_rules_active = 0;
				}

				if (udbg_enh_server_ctrl_socket_reply(
					    udbg_enh_server_ctrl_fd,
					    &udbg_enh_server_ctrl_stop_peer,
					    udbg_enh_server_ctrl_stop_peer_len,
					    reply) < 0) {
					perror("ctrl_socket_reply");
					goto udp_done;
				}
				continue;
			}
		}

		if (!FD_ISSET(fd, &rfds))
			continue;

		if (batch_budget_us > 0)
			batch_start_us = monotonic_now_us();

		for (;;) {
			if (udbg_enh_server_should_stop())
				break;
			socklen_t slen = sizeof(batch_items[batch_count].src);
			ssize_t n = recvfrom(fd,
								 batch_items[batch_count].buf,
								 sizeof(batch_items[batch_count].buf),
								 0,
								 (struct sockaddr *)&batch_items[batch_count].src,
								 &slen);

			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				perror("recvfrom");
				goto udp_done;
			}

			batch_items[batch_count].len = n;
			batch_count++;

			if (batch_count >= (size_t)batch_size)
				break;
			if (batch_budget_us > 0 && batch_start_us > 0) {
				uint64_t now_us = monotonic_now_us();
				if (now_us > 0 &&
					now_us - batch_start_us >= (uint64_t)batch_budget_us)
					break;
			}
		}

		if (batch_count == 0)
			continue;

		for (i = 0; i < batch_count; ++i) {
			process_udp_packet(cfg,
					   fd,
					   &subs,
					   &ring,
					   active_capture_rules,
					   &pcapng_ctx,
					   batch_items[i].buf,
					   batch_items[i].len,
					   &batch_items[i].src);
		}
	}

udp_done:
	(void)udbg_enh_pcapng_close(&pcapng_ctx);
	if (runtime_capture_rules_active)
		udbg_enh_capture_rules_deinit(&runtime_capture_rules);
	udbg_enh_ring_deinit(&ring);
	free(batch_items);
	udbg_enh_server_ctrl_socket_close(&udbg_enh_server_ctrl_ctx);
	if (fd >= 0)
		close(fd);
	subs_deinit(&subs);
	return;
}

/*
 * run_tcp_server: TCP server backend placeholder implementation.
 * @cfg: Server configuration (unused).
 * @capture_rules: Capture rules object (unused).
 * @output: No return value.
 */
static void run_tcp_server(const struct udbg_enh_config *cfg,
			   const struct udbg_enh_capture_rules *capture_rules)
{
	fprintf(stderr, "TCP server not available\n");
}

/*
 * udbg_enh_server_run: Load optional capture rules and start server backend.
 * @cfg: Server configuration selecting transport and runtime settings.
 * @capture_rules_path: Optional filesystem path to capture rules file.
 * @control_socket_path: Optional control socket path override.
 * @startup_capture_path: Optional startup capture output path from -f.
 * @output: No return value.
 */
void udbg_enh_server_run(const struct udbg_enh_config *cfg,
			 const char *capture_rules_path,
			 const char *control_socket_path,
			 const char *startup_capture_path)
{
	struct udbg_enh_capture_rules capture_rules = { 0 };
	char rules_err[192];

	if (!cfg)
		return;
	if (capture_rules_path && capture_rules_path[0] != '\0') {
		if (udbg_enh_capture_rules_load(&capture_rules, capture_rules_path,
					rules_err, sizeof(rules_err)) < 0) {
			UDBG_ENH_LOG("capture rules setup failed: %s",
					rules_err[0] ? rules_err : "unknown error");
			return;
		}
	}
	udbg_enh_server_clear_stop();
	if (cfg->transport == UDBG_ENH_TRANSPORT_TCP)
		run_tcp_server(cfg, &capture_rules);
	else if (cfg->transport == UDBG_ENH_TRANSPORT_UDP)
		run_udp_server(cfg, &capture_rules, control_socket_path,
			       startup_capture_path);
	else
		UDBG_ENH_LOG("invalid transport value=%d", (int)cfg->transport);

	udbg_enh_capture_rules_deinit(&capture_rules);
	return;
}

int main(int argc, char *argv[])
{
	const char *config_path = NULL;
	const char *rules_path = NULL;
	const char *control_socket_path = NULL;
	const char *startup_capture_path = NULL;
	const char *effective_control_socket_path;
	int daemonize = 0;
	struct udbg_enh_config cfg;
	int c;

	memset(&cfg, 0, sizeof(cfg));

	for (;;) {
		c = getopt(argc, argv, "Bc:r:s:f:h");
		if (c < 0)
			break;

		switch (c) {
		case 'B':
			daemonize = 1;
			break;
		case 'c':
			config_path = optarg;
			break;
		case 'r':
			rules_path = optarg;
			break;
		case 's':
			control_socket_path = optarg;
			break;
		case 'f':
			startup_capture_path = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		case '?':
		default:
			if (optopt == '-' && optind < argc &&
			    strcmp(argv[optind], "--help") == 0) {
				usage(argv[0]);
				return 0;
			}
			usage(argv[0]);
			return 1;
		}
	}

	if (optind != argc) {
		usage(argv[0]);
		return 1;
	}

	if (!config_path || config_path[0] == '\0') {
		fprintf(stderr, "Missing required -c <config-file>\n");
		usage(argv[0]);
		return 1;
	}
	if (control_socket_path && control_socket_path[0] == '\0') {
		fprintf(stderr, "Invalid -s <ctrl-socket>: path must not be empty\n");
		return 1;
	}
	if (control_socket_path &&
	    strlen(control_socket_path) > UNIX_SOCK_PATH_MAX) {
		fprintf(stderr,
			"Invalid -s <ctrl-socket>: path length must be <= %u\n",
			(unsigned int)UNIX_SOCK_PATH_MAX);
		return 1;
	}
	if (startup_capture_path && startup_capture_path[0] == '\0') {
		fprintf(stderr, "Invalid -f <pcapng-file>: path must not be empty\n");
		return 1;
	}
	if (startup_capture_path &&
	    strlen(startup_capture_path) >= PATH_MAX) {
		fprintf(stderr,
			"Invalid -f <pcapng-file>: path length must be <= %u\n",
			(unsigned int)(PATH_MAX - 1));
		return 1;
	}
	effective_control_socket_path =
		(control_socket_path && control_socket_path[0] != '\0') ?
			control_socket_path : DEFAULT_CONTROL_SOCKET_PATH;

	fprintf(stdout, "[udbg_enh-main] loading config from %s\n", config_path);

	if (udbg_enh_load_config(config_path, &cfg) < 0) {
		fprintf(stderr, "Failed to load %s\n", config_path);
		udbg_enh_config_deinit(&cfg);
		return 1;
	}

	fprintf(stdout, "[udbg_enh-main] config loaded ip=%s server_port=%u "
			"max_subscriptions=%u max_log_entries=%u transport=%s "
			"udp_batch_enable=%d udp_batch_size=%u udp_batch_budget_us=%u "
			"liveness_check_interval_ms=%u stale_timeout_ms=%u "
			"control_socket=%s\n",
			cfg.server_ip,
			(unsigned int)cfg.server_port,
			(unsigned int)cfg.server_max_subscriptions,
			(unsigned int)cfg.server_max_log_entries,
			transport_name(cfg.transport),
			cfg.udp_batch_enable,
			(unsigned int)cfg.udp_batch_size,
			(unsigned int)cfg.udp_batch_budget_us,
			(unsigned int)cfg.liveness_check_interval_ms,
			(unsigned int)cfg.stale_timeout_ms,
			effective_control_socket_path
		);

	if (rules_path && rules_path[0] != '\0')
		fprintf(stdout, "[udbg_enh-main] capture rules enabled file=%s\n",
				       	rules_path);
	else
		fprintf(stdout, "[udbg_enh-main] capture rules disabled "
				"(no -r provided)\n");
	if (startup_capture_path && startup_capture_path[0] != '\0')
		fprintf(stdout, "[udbg_enh-main] startup capture enabled file=%s\n",
			startup_capture_path);
	else
		fprintf(stdout, "[udbg_enh-main] startup capture disabled "
			"(no -f provided)\n");

	if (daemonize) {
		fprintf(stdout, "[udbg_enh-main] daemon mode enabled: "
				"stdout/stderr will be redirected to /dev/null\n");

		if (udbg_enh_daemonize(0) < 0) {
			perror("udbg_enh_daemonize");
			udbg_enh_config_deinit(&cfg);
			return 1;
		}
	}

	if (install_signal_handlers() < 0) {
		perror("install_signal_handlers");
		udbg_enh_config_deinit(&cfg);
		return 1;
	}

	fprintf(stdout, "[udbg_enh-main] starting server\n");
	udbg_enh_server_run(&cfg, rules_path, effective_control_socket_path,
			    startup_capture_path);
	udbg_enh_config_deinit(&cfg);
	return 0;
}
