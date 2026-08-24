/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include <arpa/inet.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "core.h"
#include "internal.h"
#include "nlctrl_nl80211.h"
#include "proto.h"

#define UDBG_CLIENT_CORE_MAX_INLINE_STEPS 8

void (*udbg_client_core_schedule_service_fn)(void);
void (*udbg_client_core_permanent_stop_fn)(void);

static struct udbg_client_core_state core_state;
static bool core_initialized;

static int udbg_client_core_process_rx(const void *buf, size_t len);

static int udbg_client_core_receive(void);

static void udbg_client_core_schedule_next_service(void);

static void udbg_client_core_handle_io_failure(void);

static enum udbg_client_core_connect_outcome udbg_client_core_connect(void);

static int udbg_client_core_send_subscribe(void);

static int udbg_client_core_flush_queued_internal(void);

/*
 * udbg_client_core_set_nonblocking: Enables O_NONBLOCK on a socket fd.
 * @fd: File descriptor to update.
 *
 * @output: Returns 0 on success, or -1 if fcntl operations fail.
 */
static int udbg_client_core_set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags < 0)
		return -1;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -1;

	return 0;
}

/*
 * udbg_client_core_err_invalidate: Classifies errors that should close transport.
 * @err: errno-style error code to classify.
 *
 * @output: Returns non-zero when connection should be invalidated, otherwise 0.
 */
static int udbg_client_core_err_invalidate(int err)
{
	switch (err) {
	case ECONNREFUSED:
	case EHOSTUNREACH:
	case ENETUNREACH:
	case EPIPE:
	case ENOTCONN:
		return 1;
	default:
		return 0;
	}
}

/*
 * udbg_client_core_classify_gai_error: Maps getaddrinfo failures to retry policy.
 * @gai_error: getaddrinfo() return code.
 *
 * @output: Returns connect outcome enum for retryable or permanent failure.
 */
static enum udbg_client_core_connect_outcome
udbg_client_core_classify_gai_error(int gai_error)
{
	switch (gai_error) {
#ifdef EAI_AGAIN
	case EAI_AGAIN:
		return UDBG_CLIENT_CORE_CONNECT_RETRYABLE_FAIL;
#endif
#ifdef EAI_FAMILY
	case EAI_FAMILY:
		return UDBG_CLIENT_CORE_CONNECT_PERMANENT_FAIL;
#endif
#ifdef EAI_ADDRFAMILY
	case EAI_ADDRFAMILY:
		return UDBG_CLIENT_CORE_CONNECT_PERMANENT_FAIL;
#endif
#ifdef EAI_NONAME
	case EAI_NONAME:
		return UDBG_CLIENT_CORE_CONNECT_PERMANENT_FAIL;
#endif
#ifdef EAI_BADFLAGS
	case EAI_BADFLAGS:
		return UDBG_CLIENT_CORE_CONNECT_PERMANENT_FAIL;
#endif
#ifdef EAI_SOCKTYPE
	case EAI_SOCKTYPE:
		return UDBG_CLIENT_CORE_CONNECT_PERMANENT_FAIL;
#endif
#ifdef EAI_SERVICE
	case EAI_SERVICE:
		return UDBG_CLIENT_CORE_CONNECT_PERMANENT_FAIL;
#endif
	default:
			return UDBG_CLIENT_CORE_CONNECT_PERMANENT_FAIL;
	}
}

/*
 * udbg_client_core_reset_subscription_state: Resets subscription process state to
 * idle.
 * @output: No return value; subscription_state and subscribe_handle are reset.
 */
static void udbg_client_core_reset_subscription_state(void)
{
	core_state.subscription_state = UDBG_CLIENT_CORE_SUBSCRIPTION_IDLE;
	core_state.subscribe_handle = 0;
}

static void udbg_client_core_schedule_next_service(void)
{
	if (!core_initialized ||
	    core_state.pending_step == UDBG_CLIENT_CORE_STEP_STOP_PERMANENT)
		return;

	core_state.pending_step = UDBG_CLIENT_CORE_STEP_WAIT;
}

static void udbg_client_core_handle_io_failure(void)
{
	int err = errno;

	if (!core_initialized ||
	    core_state.pending_step == UDBG_CLIENT_CORE_STEP_STOP_PERMANENT) {
		errno = err;
		return;
	}

	udbg_client_core_disconnect();
	udbg_client_core_schedule_next_service();
	errno = err;
}

/*
 * udbg_client_core_send_packet: Sends one packet via connected transport socket.
 * @buf: Packet bytes to send.
 * @len: Number of bytes to send from buf.
 *
 * @output: Returns 0 on full send success, or -1 on I/O/validation failure.
 */
static int udbg_client_core_send_packet(const void *buf, size_t len)
{
	ssize_t ret;
	int err;

	if (!core_initialized || !buf || !len) {
		errno = EINVAL;
		return -1;
	}
	if (core_state.sock_fd < 0) {
		errno = ENOTCONN;
		return -1;
	}

	ret = send(core_state.sock_fd, buf, len, 0);
	if (ret == (ssize_t) len)
		return 0;

	err = ret >= 0 ? EIO : errno;
	if (udbg_client_core_err_invalidate(err))
		udbg_client_core_disconnect();

	errno = err;
	return -1;
}

/*
 * udbg_client_core_prepare_identity: Ensures PID/UUID identity is prepared for
 * subscribe requests.
 * @output: No return value; updates identity fields when needed.
 */
static void udbg_client_core_prepare_identity(void)
{
	pid_t pid;

	if (!core_initialized)
		return;

	pid = getpid();
	if (core_state.proto_process_info.pid == pid)
		return;

	core_state.proto_process_info.pid = pid;
	if (udbg_client_core_uuid_random(core_state.proto_process_info.uuid) < 0) {
		memset(core_state.proto_process_info.uuid, 0,
		       sizeof(core_state.proto_process_info.uuid));
		memcpy(core_state.proto_process_info.uuid,
		       &core_state.proto_process_info.pid,
		       sizeof(core_state.proto_process_info.pid) <
		       sizeof(core_state.proto_process_info.uuid) ?
		       sizeof(core_state.proto_process_info.pid) :
		       sizeof(core_state.proto_process_info.uuid));
	}
}

/*
 * udbg_client_core_connect: Resolves endpoint and establishes non-blocking UDP socket.
 * @output: Returns connect outcome enum (ok/retryable/permanent fail).
 */
static enum udbg_client_core_connect_outcome udbg_client_core_connect(void)
{
	struct addrinfo hints, *result = NULL, *ai;
	struct in_addr a4;
	struct in6_addr a6;
	char port_buf[16];
	int ret;
	int fd;
	int last_errno = 0;
	enum udbg_client_core_connect_outcome outcome;

	if (!core_initialized || !core_state.server_ip[0]) {
		errno = EINVAL;
		return UDBG_CLIENT_CORE_CONNECT_PERMANENT_FAIL;
	}
	if (core_state.sock_fd >= 0) {
		core_state.pending_step = UDBG_CLIENT_CORE_STEP_SEND_SUBSCRIBE;
		return UDBG_CLIENT_CORE_CONNECT_OK;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	if (inet_pton(AF_INET, core_state.server_ip, &a4) == 1)
		hints.ai_family = AF_INET;
	else if (inet_pton(AF_INET6, core_state.server_ip, &a6) == 1)
		hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
#ifdef AI_NUMERICSERV
	hints.ai_flags |= AI_NUMERICSERV;
#endif
#ifdef AI_NUMERICHOST
	hints.ai_flags |= AI_NUMERICHOST;
#endif

	snprintf(port_buf, sizeof(port_buf), "%d", core_state.server_port);
	ret = getaddrinfo(core_state.server_ip, port_buf, &hints, &result);
	if (ret != 0) {
		outcome = udbg_client_core_classify_gai_error(ret);
		if (outcome == UDBG_CLIENT_CORE_CONNECT_RETRYABLE_FAIL)
			udbg_client_core_schedule_next_service();
		else
			core_state.pending_step =
				UDBG_CLIENT_CORE_STEP_STOP_PERMANENT;
		errno = outcome == UDBG_CLIENT_CORE_CONNECT_RETRYABLE_FAIL ?
			EAGAIN : EINVAL;
		return outcome;
	}

	for (ai = result; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) {
			last_errno = errno;
			continue;
		}

		if (udbg_client_core_set_nonblocking(fd) < 0) {
			last_errno = errno;
			close(fd);
			continue;
		}

		if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0 &&
		    errno != EINPROGRESS) {
			last_errno = errno;
			close(fd);
			continue;
		}

		core_state.sock_fd = fd;
		udbg_client_core_reset_subscription_state();
		freeaddrinfo(result);
		core_state.pending_step = UDBG_CLIENT_CORE_STEP_SEND_SUBSCRIBE;
		return UDBG_CLIENT_CORE_CONNECT_OK;
	}

	freeaddrinfo(result);
	errno = last_errno ? last_errno : EIO;
	udbg_client_core_schedule_next_service();

	return UDBG_CLIENT_CORE_CONNECT_RETRYABLE_FAIL;
}

/*
 * udbg_client_core_disconnect: Closes transport socket and clears subscription
 * process state.
 *
 * @output: No return value; socket is closed when open and state is reset.
 */
void udbg_client_core_disconnect(void)
{
	if (!core_initialized)
		return;

	if (core_state.sock_fd >= 0) {
		close(core_state.sock_fd);
		core_state.sock_fd = -1;
	}

	udbg_client_core_reset_subscription_state();
}

static void udbg_client_core_run(void)
{
	int remaining_steps = UDBG_CLIENT_CORE_MAX_INLINE_STEPS;

	if (!core_initialized) {
		errno = EINVAL;
		return;
	}

	while (remaining_steps-- > 0) {
		switch (core_state.pending_step) {
		case UDBG_CLIENT_CORE_STEP_CONNECT:
			udbg_client_core_disconnect();
			udbg_client_core_connect();
			continue;
		case UDBG_CLIENT_CORE_STEP_SEND_SUBSCRIBE:
			udbg_client_core_send_subscribe();
			continue;
		case UDBG_CLIENT_CORE_STEP_WAIT:
			if (udbg_client_core_schedule_service_fn)
				udbg_client_core_schedule_service_fn();
			return;
		case UDBG_CLIENT_CORE_STEP_STOP_PERMANENT:
			if (udbg_client_core_permanent_stop_fn)
				udbg_client_core_permanent_stop_fn();
			udbg_client_core_deinit();
			return;
		case UDBG_CLIENT_CORE_STEP_NONE:
		default:
			return;
		}
	}

	errno = ELOOP;
}

void udbg_client_core_service(bool service_timer_fired)
{
	if (!core_initialized) {
		errno = EINVAL;
		return;
	}

	if (core_state.sock_fd >= 0 &&
	    core_state.pending_step == UDBG_CLIENT_CORE_STEP_WAIT &&
	    core_state.subscription_state ==
	    UDBG_CLIENT_CORE_SUBSCRIPTION_WAIT_SUBSCRIBE_ACK &&
	    udbg_client_core_receive() < 0 &&
	    core_state.sock_fd >= 0)
		udbg_client_core_handle_io_failure();

	if (service_timer_fired &&
	    core_state.pending_step == UDBG_CLIENT_CORE_STEP_WAIT) {
		if (core_state.sock_fd < 0) {
			core_state.pending_step = UDBG_CLIENT_CORE_STEP_CONNECT;
		} else if (core_state.subscription_state ==
			   UDBG_CLIENT_CORE_SUBSCRIPTION_WAIT_SUBSCRIBE_ACK) {
			core_state.pending_step =
				UDBG_CLIENT_CORE_STEP_SEND_SUBSCRIBE;
		} else {
			core_state.pending_step = UDBG_CLIENT_CORE_STEP_NONE;
		}
	}

	udbg_client_core_run();
}

/*
 * udbg_client_core_send_subscribe: Sends subscribe request and updates
 * subscription process state.
 *
 * @output: Returns 0 on success/already-ready, or -1 on validation/send failure.
 */
static int udbg_client_core_send_subscribe(void)
{
	unsigned char msg[256];
	size_t msg_len;

	if (!core_initialized) {
		errno = EINVAL;
		return -1;
	}
	if (core_state.sock_fd < 0) {
		errno = ENOTCONN;
		udbg_client_core_handle_io_failure();
		return -1;
	}
	if (core_state.subscription_state == UDBG_CLIENT_CORE_SUBSCRIPTION_READY) {
		core_state.pending_step = UDBG_CLIENT_CORE_STEP_NONE;
		return 0;
	}

	udbg_client_core_prepare_identity();

	if (udbg_client_core_proto_build_subscribe(&core_state.proto_process_info,
						  msg, sizeof(msg), &msg_len) < 0) {
		udbg_client_core_handle_io_failure();
		return -1;
	}
	if (udbg_client_core_send_packet(msg, msg_len) < 0) {
		udbg_client_core_handle_io_failure();
		return -1;
	}

	core_state.subscription_state =
		UDBG_CLIENT_CORE_SUBSCRIPTION_WAIT_SUBSCRIBE_ACK;
	core_state.pending_step = UDBG_CLIENT_CORE_STEP_WAIT;
	return 0;
}

/*
 * udbg_client_core_flush_queued_internal: Sends queued buffered logs while
 * sendable.
 *
 * @output: Returns 0 on success, or -1 on validation/allocation/send errors.
 */
static int udbg_client_core_flush_queued_internal(void)
{
	size_t msg_cap;
	size_t msg_len = 0;
	uint8_t *msg = NULL;

	if (!core_initialized) {
		errno = EINVAL;
		return -1;
	}
	if (core_state.sock_fd < 0) {
		errno = ENOTCONN;
		return -1;
	}

	while (core_state.subscription_state ==
	       UDBG_CLIENT_CORE_SUBSCRIPTION_READY &&
	       (msg_cap = udbg_client_core_next_queued_wire_len(
		       &core_state.buffer)) > 0) {
		msg = malloc(msg_cap);
		if (!msg) {
			errno = ENOMEM;
			return -1;
		}

		if (udbg_client_core_build_next_queued_log(&core_state.buffer,
							  core_state.subscribe_handle,
							  msg, msg_cap,
							  &msg_len) < 0) {
			free(msg);
			return -1;
		}
		if (!msg_len) {
			free(msg);
			return 0;
		}
		if (udbg_client_core_send_packet(msg, msg_len) < 0) {
			free(msg);
			return -1;
		}

		udbg_client_core_buffer_pop(&core_state.buffer);
		free(msg);
	}

	return 0;
}

/*
 * udbg_client_core_send_nlctrl_nl80211_snapshot: Sends stored nlctrl/nl80211
 * snapshot immediately using the special message type.
 *
 * @output: Returns 0 when snapshot is absent or sent successfully, or -1.
 */
static int udbg_client_core_send_nlctrl_nl80211_snapshot(void)
{
	const struct udbg_client_core_nlctrl_nl80211_buffer *snapshot;
	uint64_t ts;
	size_t msg_cap;
	size_t msg_len = 0;
	uint8_t *msg = NULL;

	if (!core_initialized) {
		errno = EINVAL;
		return -1;
	}

	snapshot = &core_state.nlctrl_nl80211_buffer;
	if (!snapshot->buf || !snapshot->buf_len)
		return 0;

	if (snapshot->buf_len > (SIZE_MAX - UDBG_MSG_HEADER_SIZE -
				 UDBG_MSG_LOG_PREFIX_SIZE)) {
		errno = EOVERFLOW;
		return -1;
	}

	msg_cap = UDBG_MSG_HEADER_SIZE + UDBG_MSG_LOG_PREFIX_SIZE +
		  snapshot->buf_len;
	msg = malloc(msg_cap);
	if (!msg) {
		errno = ENOMEM;
		return -1;
	}

	ts = udbg_client_core_timestamp_us();
	if (udbg_client_core_proto_build_log(core_state.subscribe_handle,
					     UDBG_NLCTRL_NL80211, ts,
					     snapshot->buf, snapshot->buf_len,
					     msg, msg_cap, &msg_len) < 0) {
		free(msg);
		return -1;
	}

	if (!msg_len) {
		free(msg);
		return 0;
	}

	if (udbg_client_core_send_packet(msg, msg_len) < 0) {
		free(msg);
		return -1;
	}

	free(msg);
	return 0;
}

/*
 * udbg_client_core_send_log: Queues one data log payload and flushes queue when
 * transport state allows.
 * @msg_type: Message type to encode in the log frame.
 * @payload: Log payload bytes to send.
 * @payload_len: Number of payload bytes.
 *
 * @output: No return value; queues payload and updates orchestration state.
 */
void udbg_client_core_send_log(uint32_t msg_type, const void *payload,
	size_t payload_len)
{
	if (!core_initialized || !payload || !payload_len) {
		errno = EINVAL;
		return;
	}
	switch (msg_type) {
	case UDBG_NL_RX:
		if (is_nlctrl_nl80211(payload, payload_len))
			udbg_client_core_add_to_nlctrl_nl80211_buffer(
					&core_state.nlctrl_nl80211_buffer,
					payload, payload_len);
		break;
	case UDBG_NL_TX:
	case UDBG_LOG:
		break;
	default:
		errno = EINVAL;
		return;
	}

	if (udbg_client_core_queue_log(&core_state.buffer, msg_type, payload,
				       payload_len) < 0)
		return;

	if (core_state.sock_fd >= 0 &&
	    core_state.subscription_state ==
	    UDBG_CLIENT_CORE_SUBSCRIPTION_READY &&
	    udbg_client_core_flush_queued_internal() < 0) {
		udbg_client_core_handle_io_failure();
		return;
	}

	if (core_state.sock_fd < 0 &&
	    core_state.pending_step != UDBG_CLIENT_CORE_STEP_WAIT &&
	    core_state.pending_step != UDBG_CLIENT_CORE_STEP_STOP_PERMANENT)
		core_state.pending_step = UDBG_CLIENT_CORE_STEP_CONNECT;
}

/*
 * udbg_client_core_process_rx: Parses incoming control message and computes
 * follow-up orchestration state.
 * @buf: Raw received message bytes.
 * @len: Length of buf in bytes.
 *
 * @output: Returns 0 on successful processing, or -1 on parse/argument errors.
 */
static int udbg_client_core_process_rx(const void *buf, size_t len)
{
	struct udbg_client_core_buffer *buffer;
	struct udbg_client_core_proto_parsed msg;

	if (!core_initialized || !buf) {
		errno = EINVAL;
		return -1;
	}
	buffer = &core_state.buffer;

	if (udbg_client_core_proto_parse(buf, len, &msg) < 0)
		return -1;

	switch (msg.msg_type) {
	case UDBG_SUBSCRIBE_RESP:
		if (!msg.has_subscribe_resp ||
		    core_state.subscription_state !=
		    UDBG_CLIENT_CORE_SUBSCRIPTION_WAIT_SUBSCRIBE_ACK) {
			errno = EPROTO;
			return 0;
		}
		if (msg.subscribe_status == 1 && msg.handle != 0) {
			core_state.subscribe_handle = msg.handle;
			core_state.subscription_state =
				UDBG_CLIENT_CORE_SUBSCRIPTION_READY;
			core_state.pending_step = UDBG_CLIENT_CORE_STEP_NONE;
			if (core_state.nlctrl_nl80211_buffer.buf &&
			    core_state.nlctrl_nl80211_buffer.buf_len &&
			    udbg_client_core_send_nlctrl_nl80211_snapshot() < 0) {
				udbg_client_core_handle_io_failure();
				return -1;
			}
			if (buffer->count &&
			    udbg_client_core_flush_queued_internal() < 0) {
				udbg_client_core_handle_io_failure();
				return -1;
			}
			return 0;
		}

		udbg_client_core_handle_io_failure();
		return 0;
	default:
		return 0;
	}
}

/*
 * udbg_client_core_receive: Drains received packets and updates orchestration.
 *
 * @output: Returns 0 when recv loop drains without fatal errors, or -1 on failure.
 */
static int udbg_client_core_receive(void)
{
	if (!core_initialized) {
		errno = EINVAL;
		return -1;
	}
	if (core_state.sock_fd < 0) {
		errno = ENOTCONN;
		return -1;
	}

	for (;;) {
		uint8_t buf[2048];
		ssize_t len;
		int err;

		len = recv(core_state.sock_fd, buf, sizeof(buf), 0);
		if (len > 0) {
			if (udbg_client_core_process_rx(buf, (size_t) len) < 0) {
				if (core_state.sock_fd < 0) {
					errno = ENOTCONN;
					return -1;
				}
				continue;
			}
			continue;
		}

		if (len == 0)
			continue;

		err = errno;
		if (err == EAGAIN || err == EWOULDBLOCK)
			return 0;

		if (udbg_client_core_err_invalidate(err))
			udbg_client_core_handle_io_failure();

		errno = err;
		return -1;
	}
}

/*
 * udbg_client_core_init: Initializes the client core singleton.
 * @server_ip: Destination numeric IPv4/IPv6 endpoint string.
 * NULL/empty falls back to default endpoint.
 * @server_port: Destination UDP port (49152..65535). Values <= 0 use default.
 * @app_id: Application id used in subscribe identity. NULL/empty uses default.
 * @buffer_capacity: Buffered record capacity. 0 uses default.
 * @buffer_max_bytes: Buffered payload byte limit. 0 uses default.
 *
 * @output: Returns 0 on success, or -1 with errno on initialization failure.
 */
int udbg_client_core_init(const char *server_ip, int server_port, const char *app_id,
	size_t buffer_capacity, size_t buffer_max_bytes)
{
	struct udbg_client_core_state new_state;
	struct in_addr a4;
	struct in6_addr a6;

	if (core_initialized) {
		errno = EALREADY;
		return -1;
	}

	if (!server_ip || !server_ip[0])
		server_ip = UDBG_CLIENT_CORE_SERVER_IP;
	if (server_port <= 0)
		server_port = UDBG_CLIENT_CORE_SERVER_PORT;
	if (!app_id || !app_id[0])
		app_id = UDBG_CLIENT_CORE_CLIENT_APP_ID;
	if (!buffer_capacity)
		buffer_capacity = UDBG_CLIENT_CORE_BUFFER_DEFAULT_CAPACITY;
	if (!buffer_max_bytes)
		buffer_max_bytes = UDBG_CLIENT_CORE_BUFFER_DEFAULT_MAX_BYTES;

	if (!app_id[0] || strlen(app_id) >= UDBG_CLIENT_CORE_APP_ID_SIZE ||
	    !server_ip[0] || strlen(server_ip) >= UDBG_CLIENT_CORE_SERVER_IP_SIZE ||
	    server_port < 49152 || server_port > 65535 ||
		!buffer_capacity || !buffer_max_bytes ||
	    buffer_capacity > UDBG_CLIENT_CORE_BUFFER_MAX_CAPACITY ||
	    buffer_max_bytes > UDBG_CLIENT_CORE_BUFFER_MAX_BYTES_LIMIT) {
		errno = EINVAL;
		return -1;
	}

	if (inet_pton(AF_INET, server_ip, &a4) != 1 &&
	    inet_pton(AF_INET6, server_ip, &a6) != 1) {
		errno = EINVAL;
		return -1;
	}

	memset(&new_state, 0, sizeof(new_state));
	snprintf(new_state.server_ip, sizeof(new_state.server_ip), "%s",
		 server_ip);
	snprintf(new_state.proto_process_info.app_id,
		 sizeof(new_state.proto_process_info.app_id), "%s", app_id);
	new_state.server_port = server_port;

	new_state.sock_fd = -1;
	new_state.subscription_state = UDBG_CLIENT_CORE_SUBSCRIPTION_IDLE;
	new_state.pending_step = UDBG_CLIENT_CORE_STEP_CONNECT;
	if (udbg_client_core_buffer_init(&new_state.buffer,
						     buffer_capacity,
						     buffer_max_bytes) < 0)
		return -1;
	udbg_client_core_nlctrl_nl80211_buffer_init(
		&new_state.nlctrl_nl80211_buffer);
	core_state = new_state;
	core_initialized = true;
	return 0;
}

/*
 * udbg_client_core_deinit: Releases all resources owned by the core singleton.
 *
 * @output: No return value; safely frees core internals.
 */
void udbg_client_core_deinit(void)
{
	if (!core_initialized)
		return;

	udbg_client_core_disconnect();
	udbg_client_core_buffer_deinit(&core_state.buffer);
	udbg_client_core_nlctrl_nl80211_buffer_deinit(
		&core_state.nlctrl_nl80211_buffer);
	memset(&core_state, 0, sizeof(core_state));
	core_initialized = false;
}
