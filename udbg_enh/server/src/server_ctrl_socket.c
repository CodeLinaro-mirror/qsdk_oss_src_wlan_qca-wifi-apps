// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "server_ctrl_socket.h"
#include "config.h"
#include "utils.h"

/*
 * udbg_enh_server_ctrl_sockaddr_set: Build UNIX socket address from path.
 * @addr: Destination sockaddr_un to populate.
 * @addr_len: Destination for computed sockaddr length.
 * @path: Socket path string to encode.
 * @output: Returns 0 on success, -1 on validation/size failure.
 */
static int udbg_enh_server_ctrl_sockaddr_set(struct sockaddr_un *addr,
					     socklen_t *addr_len,
					     const char *path)
{
	size_t path_len;

	if (!addr || !addr_len || !path || path[0] == '\0') {
		errno = EINVAL;
		return -1;
	}

	path_len = strlen(path);
	if (path_len >= sizeof(addr->sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	memcpy(addr->sun_path, path, path_len + 1);
	*addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
				path_len + 1);
	return 0;
}

/*
 * udbg_enh_server_ctrl_socket_is_stale: Check whether existing socket is stale.
 * @path: UNIX socket path to probe.
 * @output: Returns 1 for stale path, 0 for live peer, -1 on probe error.
 */
static int udbg_enh_server_ctrl_socket_is_stale(const char *path)
{
	int fd;
	struct sockaddr_un addr;
	socklen_t addr_len;
	int rc;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	if (udbg_enh_server_ctrl_sockaddr_set(&addr, &addr_len, path) < 0) {
		close(fd);
		return -1;
	}

	rc = connect(fd, (struct sockaddr *)&addr, addr_len);
	if (rc == 0) {
		close(fd);
		return 0;
	}

	if (errno == ECONNREFUSED || errno == ENOENT || errno == ENOTSOCK) {
		close(fd);
		return 1;
	}

	close(fd);
	return -1;
}

/*
 * udbg_enh_server_ctrl_socket_open: Open and bind server control socket.
 * @ctx: Socket context to initialize.
 * @path: UNIX socket path to bind.
 * @output: Returns 0 on success, -1 on validation/socket/bind failure.
 */
int udbg_enh_server_ctrl_socket_open(struct udbg_enh_server_ctrl_socket *ctx,
					     const char *path)
{
	int fd;
	struct sockaddr_un addr;
	socklen_t addr_len;
	char *dup_path;

	if (!ctx || !path || path[0] == '\0') {
		errno = EINVAL;
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = -1;

	dup_path = udbg_enh_path_dup(path, UNIX_SOCK_PATH_MAX + 1u);
	if (!dup_path) {
		errno = ENAMETOOLONG;
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		free(dup_path);
		return -1;
	}

	if (udbg_enh_set_nonblocking(fd) < 0) {
		close(fd);
		free(dup_path);
		return -1;
	}

	if (udbg_enh_server_ctrl_sockaddr_set(&addr, &addr_len, dup_path) < 0) {
		close(fd);
		free(dup_path);
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&addr, addr_len) < 0) {
		if (errno == EADDRINUSE) {
			int stale = udbg_enh_server_ctrl_socket_is_stale(dup_path);

			if (stale == 1) {
				if (unlink(dup_path) < 0 && errno != ENOENT) {
					close(fd);
					free(dup_path);
					return -1;
				}
				if (bind(fd, (struct sockaddr *)&addr, addr_len) < 0) {
					close(fd);
					free(dup_path);
					return -1;
				}
			} else {
				close(fd);
				free(dup_path);
				if (stale == 0)
					errno = EADDRINUSE;
				return -1;
			}
		} else {
			close(fd);
			free(dup_path);
			return -1;
		}
	}

	ctx->fd = fd;
	ctx->path = dup_path;
	return 0;
}

/*
 * udbg_enh_server_ctrl_socket_close: Close control socket and remove path.
 * @ctx: Socket context to close.
 * @output: No return value.
 */
void udbg_enh_server_ctrl_socket_close(struct udbg_enh_server_ctrl_socket *ctx)
{
	if (!ctx)
		return;

	if (ctx->fd >= 0)
		close(ctx->fd);
	ctx->fd = -1;

	if (ctx->path) {
		if (unlink(ctx->path) < 0)
                        perror("unlink");
		free(ctx->path);
		ctx->path = NULL;
	}
}

/*
 * udbg_enh_server_ctrl_socket_get_fd: Read current control socket fd.
 * @ctx: Socket context to query.
 * @output: Returns socket fd, or -1 when @ctx is invalid.
 */
int udbg_enh_server_ctrl_socket_get_fd(const struct udbg_enh_server_ctrl_socket *ctx)
{
	if (!ctx)
		return -1;
	return ctx->fd;
}

/*
 * udbg_enh_server_ctrl_socket_reply: Send reply to one peer endpoint.
 * @fd: Bound socket fd used for send.
 * @peer: Destination UNIX peer address.
 * @peer_len: Size of @peer in bytes.
 * @reply: Reply payload to send.
 * @output: Returns 0 on success, -1 on validation/send failure.
 */
int udbg_enh_server_ctrl_socket_reply(int fd,
				      const struct sockaddr_un *peer,
				      socklen_t peer_len,
				      const char *reply)
{
	size_t reply_len;
	ssize_t sent;

	if (fd < 0 || !peer || peer_len == 0 || !reply) {
		errno = EINVAL;
		return -1;
	}

	reply_len = strlen(reply);
	sent = sendto(fd, reply, reply_len, 0,
		      (const struct sockaddr *)peer, peer_len);
	if (sent < 0)
		return -1;
	if ((size_t)sent != reply_len) {
		errno = EIO;
		return -1;
	}

	return 0;
}

/*
 * udbg_enh_server_ctrl_socket_parse_command: Normalize and parse command text.
 * @buf: Mutable command buffer to trim and normalize in place.
 * @len: Number of bytes received into @buf.
 * @output: Returns parsed command enum value.
 */
static int udbg_enh_server_ctrl_socket_parse_command(char *buf, ssize_t len)
{
	size_t start = 0;
	size_t end;
	size_t cmd_len;

	if (!buf || len <= 0)
		return UDBG_ENH_SERVER_CTRL_CMD_INVALID;

	end = (size_t)len;
	while (end > 0 && isspace((unsigned char)buf[end - 1]))
		--end;
	while (start < end && isspace((unsigned char)buf[start]))
		++start;
	if (start >= end)
		return UDBG_ENH_SERVER_CTRL_CMD_INVALID;

	cmd_len = end - start;
	if (start > 0)
		memmove(buf, buf + start, cmd_len);
	buf[cmd_len] = '\0';

	if (strcmp(buf, UDBG_ENH_SERVER_CTRL_CMD_PING_STR) == 0)
		return UDBG_ENH_SERVER_CTRL_CMD_PING;
	if (strcmp(buf, UDBG_ENH_SERVER_CTRL_CMD_TERMINATE_STR) == 0)
		return UDBG_ENH_SERVER_CTRL_CMD_TERMINATE;
	if (strncmp(buf, UDBG_ENH_SERVER_CTRL_CMD_FLUSH_STR,
		    strlen(UDBG_ENH_SERVER_CTRL_CMD_FLUSH_STR)) == 0) {
		const char *suffix = buf + strlen(UDBG_ENH_SERVER_CTRL_CMD_FLUSH_STR);

		if (*suffix == '\0' || isspace((unsigned char)*suffix))
			return UDBG_ENH_SERVER_CTRL_CMD_FLUSH;
	}
	if (strncmp(buf, UDBG_ENH_SERVER_CTRL_CMD_START_STR,
		    strlen(UDBG_ENH_SERVER_CTRL_CMD_START_STR)) == 0) {
		const char *suffix = buf + strlen(UDBG_ENH_SERVER_CTRL_CMD_START_STR);

		if (*suffix == '\0' || isspace((unsigned char)*suffix))
			return UDBG_ENH_SERVER_CTRL_CMD_START;
	}
	if (strcmp(buf, UDBG_ENH_SERVER_CTRL_CMD_STOP_STR) == 0)
		return UDBG_ENH_SERVER_CTRL_CMD_STOP;
	return UDBG_ENH_SERVER_CTRL_CMD_INVALID;
}

static int udbg_enh_server_ctrl_parse_file_rules_args(const char *cmd,
						      const char *cmd_prefix,
						      char *file_name,
						      size_t file_name_len,
						      char *rules_file_name,
						      size_t rules_file_name_len)
{
	const char *p;
	int have_file_name = 0;

	if (!cmd || !cmd_prefix || !file_name || file_name_len == 0 ||
	    !rules_file_name || rules_file_name_len == 0)
		return -1;

	file_name[0] = '\0';
	rules_file_name[0] = '\0';

	p = cmd;
	if (strncmp(p, cmd_prefix, strlen(cmd_prefix)) != 0)
		return -1;
	p += strlen(cmd_prefix);

	while (*p != '\0') {
		size_t value_len;
		char *out_buf;
		size_t out_buf_len;

		while (*p != '\0' && isspace((unsigned char)*p))
			++p;
		if (*p == '\0')
			break;

		if (strncmp(p, "-f", 2) == 0 &&
		    (p[2] == '\0' || isspace((unsigned char)p[2]))) {
			if (have_file_name)
				return -1;
			out_buf = file_name;
			out_buf_len = file_name_len;
			have_file_name = 1;
			p += 2;
		} else if (strncmp(p, "-r", 2) == 0 &&
			   (p[2] == '\0' || isspace((unsigned char)p[2]))) {
			if (rules_file_name[0] != '\0')
				return -1;
			out_buf = rules_file_name;
			out_buf_len = rules_file_name_len;
			p += 2;
		} else {
			return -1;
		}

		while (*p != '\0' && isspace((unsigned char)*p))
			++p;
		if (*p == '\0')
			return -1;

		value_len = strcspn(p, " \t\r\n");
		if (value_len == 0 || value_len >= out_buf_len)
			return -1;
		memcpy(out_buf, p, value_len);
		out_buf[value_len] = '\0';
		p += value_len;
	}

	return have_file_name ? 0 : -1;
}

/*
 * udbg_enh_server_ctrl_socket_handle_one: Process one pending control message.
 * @ctx: Open control socket context.
 * @terminate_requested: Optional flag set to 1 on TERMINATE command.
 * @flush_requested: Optional flag set to 1 on valid FLUSH request.
 * @flush_file_name: Optional buffer receiving FLUSH output file path.
 * @flush_file_name_len: Size of @flush_file_name in bytes.
 * @flush_rules_file_name: Optional buffer receiving FLUSH capture-rules path.
 * @flush_rules_file_name_len: Size of @flush_rules_file_name in bytes.
 * @flush_peer: Optional FLUSH command sender address for deferred reply.
 * @flush_peer_len: Optional length of @flush_peer.
 * @start_requested: Optional flag set to 1 on valid START request.
 * @start_file_name: Optional buffer receiving START output file path.
 * @start_file_name_len: Size of @start_file_name in bytes.
 * @start_rules_file_name: Optional buffer receiving START capture-rules path.
 * @start_rules_file_name_len: Size of @start_rules_file_name in bytes.
 * @start_peer: Optional START command sender address for deferred reply.
 * @start_peer_len: Optional length of @start_peer.
 * @stop_requested: Optional flag set to 1 on STOP request.
 * @stop_peer: Optional STOP command sender address for deferred reply.
 * @stop_peer_len: Optional length of @stop_peer.
 * @output: Returns 0 on handled/no data, -1 on recv/send failure.
 */
int udbg_enh_server_ctrl_socket_handle_one(struct udbg_enh_server_ctrl_socket *ctx,
					   int *terminate_requested,
					   int *flush_requested,
					   char *flush_file_name,
					   size_t flush_file_name_len,
					   char *flush_rules_file_name,
					   size_t flush_rules_file_name_len,
					   struct sockaddr_un *flush_peer,
					   socklen_t *flush_peer_len,
					   int *start_requested,
					   char *start_file_name,
					   size_t start_file_name_len,
					   char *start_rules_file_name,
					   size_t start_rules_file_name_len,
					   struct sockaddr_un *start_peer,
					   socklen_t *start_peer_len,
					   int *stop_requested,
					   struct sockaddr_un *stop_peer,
					   socklen_t *stop_peer_len)
{
	struct sockaddr_un peer;
	socklen_t peer_len = sizeof(peer);
	char buf[(2u * PATH_MAX) + 64u];
	ssize_t n;
	int cmd_id;

	if (!ctx || ctx->fd < 0) {
		errno = EINVAL;
		return -1;
	}
	if (terminate_requested)
		*terminate_requested = 0;
	if (flush_requested)
		*flush_requested = 0;
	if (start_requested)
		*start_requested = 0;
	if (stop_requested)
		*stop_requested = 0;
	if (flush_file_name && flush_file_name_len > 0)
		flush_file_name[0] = '\0';
	if (flush_rules_file_name && flush_rules_file_name_len > 0)
		flush_rules_file_name[0] = '\0';
	if (start_file_name && start_file_name_len > 0)
		start_file_name[0] = '\0';
	if (start_rules_file_name && start_rules_file_name_len > 0)
		start_rules_file_name[0] = '\0';

	n = recvfrom(ctx->fd, buf, sizeof(buf) - 1, 0,
		     (struct sockaddr *)&peer, &peer_len);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		return -1;
	}

	cmd_id = udbg_enh_server_ctrl_socket_parse_command(buf, n);
	switch (cmd_id) {
	case UDBG_ENH_SERVER_CTRL_CMD_PING:
		return udbg_enh_server_ctrl_socket_reply(ctx->fd, &peer, peer_len,
							UDBG_ENH_SERVER_CTRL_REPLY_PONG_STR);
	case UDBG_ENH_SERVER_CTRL_CMD_TERMINATE:
		if (udbg_enh_server_ctrl_socket_reply(ctx->fd, &peer, peer_len,
						     UDBG_ENH_SERVER_CTRL_REPLY_OK_STR) < 0)
			return -1;
		if (terminate_requested)
			*terminate_requested = 1;
		return 0;
	case UDBG_ENH_SERVER_CTRL_CMD_FLUSH:
		if (!flush_requested || !flush_file_name || flush_file_name_len == 0 ||
		    !flush_rules_file_name || flush_rules_file_name_len == 0 ||
		    !flush_peer || !flush_peer_len)
			return udbg_enh_server_ctrl_socket_reply(
				ctx->fd, &peer, peer_len, UDBG_ENH_SERVER_CTRL_REPLY_FAIL_STR);
		if (udbg_enh_server_ctrl_parse_file_rules_args(
			    buf,
			    UDBG_ENH_SERVER_CTRL_CMD_FLUSH_STR,
			    flush_file_name,
			    flush_file_name_len,
			    flush_rules_file_name,
			    flush_rules_file_name_len) < 0)
			return udbg_enh_server_ctrl_socket_reply(
				ctx->fd, &peer, peer_len, UDBG_ENH_SERVER_CTRL_REPLY_FAIL_STR);
		*flush_requested = 1;
		*flush_peer = peer;
		*flush_peer_len = peer_len;
		return 0;
	case UDBG_ENH_SERVER_CTRL_CMD_START:
		if (!start_requested || !start_file_name || start_file_name_len == 0 ||
		    !start_rules_file_name || start_rules_file_name_len == 0 ||
		    !start_peer || !start_peer_len)
			return udbg_enh_server_ctrl_socket_reply(
				ctx->fd, &peer, peer_len, UDBG_ENH_SERVER_CTRL_REPLY_FAIL_STR);
		if (udbg_enh_server_ctrl_parse_file_rules_args(
			    buf,
			    UDBG_ENH_SERVER_CTRL_CMD_START_STR,
			    start_file_name,
			    start_file_name_len,
			    start_rules_file_name,
			    start_rules_file_name_len) < 0)
			return udbg_enh_server_ctrl_socket_reply(
				ctx->fd, &peer, peer_len, UDBG_ENH_SERVER_CTRL_REPLY_FAIL_STR);
		*start_requested = 1;
		*start_peer = peer;
		*start_peer_len = peer_len;
		return 0;
	case UDBG_ENH_SERVER_CTRL_CMD_STOP:
		if (!stop_requested || !stop_peer || !stop_peer_len)
			return udbg_enh_server_ctrl_socket_reply(
				ctx->fd, &peer, peer_len, UDBG_ENH_SERVER_CTRL_REPLY_FAIL_STR);
		*stop_requested = 1;
		*stop_peer = peer;
		*stop_peer_len = peer_len;
		return 0;
	default:
		return udbg_enh_server_ctrl_socket_reply(ctx->fd, &peer, peer_len,
							UDBG_ENH_SERVER_CTRL_REPLY_FAIL_STR);
	}
}
