// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "server_ctrl_socket.h"
#include "config.h"
#include "utils.h"

struct udbg_enh_server_ctrl_client {
	int fd;
	char *local_path;
	struct sockaddr_un server_addr;
	socklen_t server_addr_len;
};

static const char *udbg_enh_server_control_socket_default_path =
	DEFAULT_CONTROL_SOCKET_PATH;

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
 * udbg_enh_server_ctrl_make_client_path: Generate unique local client path.
 * @out: Destination buffer for generated path.
 * @out_len: Size of @out in bytes.
 * @output: Returns 0 on success, -1 on validation/length failure.
 */
static int udbg_enh_server_ctrl_make_client_path(char *out, size_t out_len)
{
	int n;
	uint64_t now_us = monotonic_now_us();

	if (!out || out_len == 0) {
		errno = EINVAL;
		return -1;
	}

	n = snprintf(out, out_len,
		     "/tmp/udbg_enh_server_cli_%ld_%llu.sock",
		     (long)getpid(),
		     (unsigned long long)now_us);
	if (n <= 0 || (size_t)n >= out_len) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return 0;
}

/*
 * udbg_enh_server_ctrl_socket_resolve_path: Resolve override or default path.
 * @socket_override: Optional non-empty socket path override.
 * @output: Returns resolved socket path string.
 */
static const char *udbg_enh_server_ctrl_socket_resolve_path(
	const char *socket_override)
{
	if (socket_override && socket_override[0] != '\0')
		return socket_override;
	return udbg_enh_server_control_socket_default_path;
}

/*
 * udbg_enh_server_ctrl_client_open: Open and bind control client endpoint.
 * @ctx: Client context to initialize.
 * @server_path: Optional server socket path override.
 * @output: Returns 0 on success, -1 on socket/setup failure.
 */
static int udbg_enh_server_ctrl_client_open(struct udbg_enh_server_ctrl_client *ctx,
					    const char *server_path)
{
	int fd;
	char local_path[UNIX_SOCK_PATH_MAX + 1u];
	socklen_t local_addr_len;
	struct sockaddr_un local_addr;
	const char *resolved_path;

	if (!ctx) {
		errno = EINVAL;
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = -1;

	resolved_path = udbg_enh_server_ctrl_socket_resolve_path(server_path);
	if (!resolved_path || resolved_path[0] == '\0') {
		errno = EINVAL;
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	if (udbg_enh_set_nonblocking(fd) < 0) {
		close(fd);
		return -1;
	}

	if (udbg_enh_server_ctrl_make_client_path(local_path, sizeof(local_path)) <
	    0) {
		close(fd);
		return -1;
	}

	if (udbg_enh_server_ctrl_sockaddr_set(&local_addr, &local_addr_len,
					      local_path) < 0) {
		close(fd);
		return -1;
	}

	if (unlink(local_path) < 0 && errno != ENOENT) {
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&local_addr, local_addr_len) < 0) {
		close(fd);
		if (unlink(local_path) < 0) 
			perror("unlink");
		return -1;
	}

	if (udbg_enh_server_ctrl_sockaddr_set(&ctx->server_addr,
					      &ctx->server_addr_len,
					      resolved_path) < 0) {
		close(fd);
		if (unlink(local_path) < 0)
			perror("unlink");
		return -1;
	}

	ctx->local_path = udbg_enh_path_dup(local_path,
					    UNIX_SOCK_PATH_MAX + 1u);
	if (!ctx->local_path) {
		close(fd);
		if (unlink(local_path) < 0)
                        perror("unlink");
		errno = ENAMETOOLONG;
		return -1;
	}

	ctx->fd = fd;
	return 0;
}

/*
 * udbg_enh_server_ctrl_client_close: Close client socket and remove local path.
 * @ctx: Client context to close.
 * @output: No return value.
 */
static void udbg_enh_server_ctrl_client_close(
	struct udbg_enh_server_ctrl_client *ctx)
{
	if (!ctx)
		return;

	if (ctx->fd >= 0)
		close(ctx->fd);
	ctx->fd = -1;

	if (ctx->local_path) {
		if (unlink(ctx->local_path) < 0)
                        perror("unlink");
		free(ctx->local_path);
		ctx->local_path = NULL;
	}
}

/*
 * udbg_enh_server_ctrl_client_request: Send command and validate reply.
 * @ctx: Open client context used for request/response.
 * @cmd: Command string to send.
 * @expect: Exact response string expected from server.
 * @timeout_ms: Request timeout in milliseconds (0 uses default).
 * @output: Returns 0 on expected reply, -1 on send/timeout/reply failure.
 */
static int udbg_enh_server_ctrl_client_request(
	struct udbg_enh_server_ctrl_client *ctx,
	const char *cmd,
	const char *expect,
	unsigned int timeout_ms)
{
	size_t cmd_len;
	size_t expect_len;
	ssize_t sent;
	uint64_t deadline_us;

	if (!ctx || ctx->fd < 0 || !cmd || !expect) {
		errno = EINVAL;
		return -1;
	}

	cmd_len = strlen(cmd);
	expect_len = strlen(expect);
	sent = sendto(ctx->fd, cmd, cmd_len, 0,
		      (struct sockaddr *)&ctx->server_addr,
		      ctx->server_addr_len);
	if (sent < 0)
		return -1;
	if ((size_t)sent != cmd_len) {
		errno = EIO;
		return -1;
	}

	if (timeout_ms == 0)
		timeout_ms = DEFAULT_STOP_TIMEOUT_MS;
	deadline_us = monotonic_now_us() + ((uint64_t)timeout_ms * 1000ull);

	for (;;) {
		fd_set rfds;
		struct timeval tv;
		uint64_t now_us;
		uint64_t remain_us;
		int sel_rc;
		char reply[64];
		ssize_t n;

		now_us = monotonic_now_us();
		if (now_us >= deadline_us) {
			errno = ETIMEDOUT;
			return -1;
		}
		remain_us = deadline_us - now_us;

		FD_ZERO(&rfds);
		FD_SET(ctx->fd, &rfds);
		tv.tv_sec = (time_t)(remain_us / 1000000ull);
		tv.tv_usec = (suseconds_t)((remain_us % 1000000ull));

		sel_rc = select(ctx->fd + 1, &rfds, NULL, NULL, &tv);
		if (sel_rc < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (sel_rc == 0) {
			errno = ETIMEDOUT;
			return -1;
		}

		n = recvfrom(ctx->fd, reply, sizeof(reply) - 1, 0, NULL, NULL);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR)
				continue;
			return -1;
		}

		reply[n] = '\0';
		if ((size_t)n == expect_len &&
		    memcmp(reply, expect, expect_len) == 0)
			return 0;

		errno = EBADMSG;
		return -1;
	}
}

/*
 * udbg_enh_server_ctrl_client_ping: Send PING control command.
 * @ctx: Open client context.
 * @timeout_ms: Request timeout in milliseconds.
 * @output: Returns 0 on PONG response, -1 on failure.
 */
static int udbg_enh_server_ctrl_client_ping(
	struct udbg_enh_server_ctrl_client *ctx,
	unsigned int timeout_ms)
{
	return udbg_enh_server_ctrl_client_request(
		ctx, UDBG_ENH_SERVER_CTRL_CMD_PING_STR,
		UDBG_ENH_SERVER_CTRL_REPLY_PONG_STR, timeout_ms);
}

/*
 * udbg_enh_server_ctrl_client_terminate: Send TERMINATE control command.
 * @ctx: Open client context.
 * @timeout_ms: Request timeout in milliseconds.
 * @output: Returns 0 on OK response, -1 on failure.
 */
static int udbg_enh_server_ctrl_client_terminate(
	struct udbg_enh_server_ctrl_client *ctx,
	unsigned int timeout_ms)
{
	return udbg_enh_server_ctrl_client_request(
		ctx, UDBG_ENH_SERVER_CTRL_CMD_TERMINATE_STR,
		UDBG_ENH_SERVER_CTRL_REPLY_OK_STR, timeout_ms);
}

/*
 * udbg_enh_server_ctrl_client_flush: Send FLUSH control command.
 * @ctx: Open client context.
 * @file_name: Output path for snapshot dump.
 * @rules_file_name: Optional capture-rules path applied during FLUSH dump.
 * @timeout_ms: Request timeout in milliseconds.
 * @output: Returns 0 on OK response, -1 on failure.
 */
static int udbg_enh_server_ctrl_client_flush(
	struct udbg_enh_server_ctrl_client *ctx,
	const char *file_name,
	const char *rules_file_name,
	unsigned int timeout_ms)
{
	char cmd[(2u * PATH_MAX) + 32u];
	int n;

	if (!file_name || file_name[0] == '\0') {
		errno = EINVAL;
		return -1;
	}

	if (rules_file_name && rules_file_name[0] != '\0')
		n = snprintf(cmd, sizeof(cmd), "%s -f %s -r %s",
			     UDBG_ENH_SERVER_CTRL_CMD_FLUSH_STR,
			     file_name,
			     rules_file_name);
	else
		n = snprintf(cmd, sizeof(cmd), "%s -f %s",
			     UDBG_ENH_SERVER_CTRL_CMD_FLUSH_STR,
			     file_name);
	if (n <= 0 || (size_t)n >= sizeof(cmd)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	return udbg_enh_server_ctrl_client_request(
		ctx, cmd, UDBG_ENH_SERVER_CTRL_REPLY_OK_STR, timeout_ms);
}

/*
 * udbg_enh_server_ctrl_client_start: Send START control command.
 * @ctx: Open client context.
 * @file_name: Output path for live capture.
 * @rules_file_name: Optional capture-rules path applied to live capture.
 * @timeout_ms: Request timeout in milliseconds.
 * @output: Returns 0 on OK response, -1 on failure.
 */
static int udbg_enh_server_ctrl_client_start(
	struct udbg_enh_server_ctrl_client *ctx,
	const char *file_name,
	const char *rules_file_name,
	unsigned int timeout_ms)
{
	char cmd[(2u * PATH_MAX) + 32u];
	int n;

	if (!file_name || file_name[0] == '\0') {
		errno = EINVAL;
		return -1;
	}

	if (rules_file_name && rules_file_name[0] != '\0')
		n = snprintf(cmd, sizeof(cmd), "%s -f %s -r %s",
			     UDBG_ENH_SERVER_CTRL_CMD_START_STR,
			     file_name,
			     rules_file_name);
	else
		n = snprintf(cmd, sizeof(cmd), "%s -f %s",
			     UDBG_ENH_SERVER_CTRL_CMD_START_STR,
			     file_name);
	if (n <= 0 || (size_t)n >= sizeof(cmd)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	return udbg_enh_server_ctrl_client_request(
		ctx, cmd, UDBG_ENH_SERVER_CTRL_REPLY_OK_STR, timeout_ms);
}

/*
 * udbg_enh_server_ctrl_client_stop: Send STOP control command.
 * @ctx: Open client context.
 * @timeout_ms: Request timeout in milliseconds.
 * @output: Returns 0 on OK response, -1 on failure.
 */
static int udbg_enh_server_ctrl_client_stop(
	struct udbg_enh_server_ctrl_client *ctx,
	unsigned int timeout_ms)
{
	return udbg_enh_server_ctrl_client_request(
		ctx, UDBG_ENH_SERVER_CTRL_CMD_STOP_STR,
		UDBG_ENH_SERVER_CTRL_REPLY_OK_STR, timeout_ms);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s  <command> [<options>] [<args>]\n"
		"\n"
		"  Options:\n"
		"    -s <ctrl-socket>            Control socket path override\n"
		"    -f <file_name>              Output pcapng file path (required for flush/start)\n"
		"    -r <rules-file>             Optional capture rules file (flush/start)\n"
		"    -h                          Show this help\n"
		"\n"
		"  Commands:\n"
		"    ping:                       Send PING and expect PONG\n"
		"    terminate:                  Send TERMINATE and expect OK\n"
		"    flush:                      Dump ring-buffer snapshot to pcapng and expect OK\n"
		"    start:                      Start live capture to pcapng and expect OK\n"
		"    stop:                       Stop live capture and expect OK\n",
		prog);
}

static enum udbg_enh_server_cli_command parse_command(const char *arg)
{
	if (!arg)
		return UDBG_ENH_SERVER_CLI_CMD_INVALID;
	if (strcmp(arg, "ping") == 0)
		return UDBG_ENH_SERVER_CLI_CMD_PING;
	if (strcmp(arg, "terminate") == 0)
		return UDBG_ENH_SERVER_CLI_CMD_TERMINATE;
	if (strcmp(arg, "flush") == 0)
		return UDBG_ENH_SERVER_CLI_CMD_FLUSH;
	if (strcmp(arg, "start") == 0)
		return UDBG_ENH_SERVER_CLI_CMD_START;
	if (strcmp(arg, "stop") == 0)
		return UDBG_ENH_SERVER_CLI_CMD_STOP;
	return UDBG_ENH_SERVER_CLI_CMD_INVALID;
}

int main(int argc, char *argv[])
{
	enum udbg_enh_server_cli_command cmd;
	const char *socket_override = NULL;
	const char *capture_file_name = NULL;
	const char *capture_rules_file_name = NULL;
	const char *socket_path;
	struct udbg_enh_server_ctrl_client udbg_enh_server_ctrl_client_ctx;
	int rc = 1;
	int c;

	memset(&udbg_enh_server_ctrl_client_ctx, 0,
	       sizeof(udbg_enh_server_ctrl_client_ctx));
	udbg_enh_server_ctrl_client_ctx.fd = -1;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		usage(argv[0]);
		return 0;
	}

	cmd = parse_command(argv[1]);
	if (cmd == UDBG_ENH_SERVER_CLI_CMD_INVALID) {
		usage(argv[0]);
		return 1;
	}

	optind = 2;
	for (;;) {
		c = getopt(argc, argv, "s:f:r:h");
		if (c < 0)
			break;

		switch (c) {
		case 's':
			socket_override = optarg;
			break;
		case 'f':
			capture_file_name = optarg;
			break;
		case 'r':
			capture_rules_file_name = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		case '?':
		default:
			if (optopt == '-' &&
			    ((optind < argc && strcmp(argv[optind], "--help") == 0) ||
			     (optind > 0 && strcmp(argv[optind - 1], "--help") == 0))) {
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
	if ((cmd == UDBG_ENH_SERVER_CLI_CMD_FLUSH ||
	     cmd == UDBG_ENH_SERVER_CLI_CMD_START) &&
	    (!capture_file_name || capture_file_name[0] == '\0')) {
		usage(argv[0]);
		return 1;
	}
	if (cmd != UDBG_ENH_SERVER_CLI_CMD_FLUSH &&
	    cmd != UDBG_ENH_SERVER_CLI_CMD_START &&
	    capture_file_name) {
		usage(argv[0]);
		return 1;
	}
	if (cmd != UDBG_ENH_SERVER_CLI_CMD_FLUSH &&
	    cmd != UDBG_ENH_SERVER_CLI_CMD_START &&
	    capture_rules_file_name) {
		usage(argv[0]);
		return 1;
	}

	socket_path = udbg_enh_server_ctrl_socket_resolve_path(socket_override);
	if (udbg_enh_server_ctrl_client_open(&udbg_enh_server_ctrl_client_ctx,
					     socket_path) < 0) {
		fprintf(stderr,
			"Failed to open control client for socket '%s': %s\n",
			socket_path ? socket_path : "<null>",
			strerror(errno));
		return 1;
	}

	if (cmd == UDBG_ENH_SERVER_CLI_CMD_PING) {
		if (udbg_enh_server_ctrl_client_ping(
			    &udbg_enh_server_ctrl_client_ctx,
			    DEFAULT_STOP_TIMEOUT_MS) < 0) {
			fprintf(stderr, "PING failed on '%s': %s\n",
				socket_path,
				strerror(errno));
			goto out;
		}
		printf("PONG\n");
	} else if (cmd == UDBG_ENH_SERVER_CLI_CMD_TERMINATE) {
		if (udbg_enh_server_ctrl_client_terminate(
			    &udbg_enh_server_ctrl_client_ctx,
			    DEFAULT_STOP_TIMEOUT_MS) < 0) {
			fprintf(stderr, "TERMINATE failed on '%s': %s\n",
				socket_path,
				strerror(errno));
			goto out;
		}
		printf("OK\n");
	} else if (cmd == UDBG_ENH_SERVER_CLI_CMD_FLUSH) {
		if (udbg_enh_server_ctrl_client_flush(
			    &udbg_enh_server_ctrl_client_ctx,
			    capture_file_name,
			    capture_rules_file_name,
			    DEFAULT_STOP_TIMEOUT_MS) < 0) {
			fprintf(stderr, "FLUSH failed on '%s': %s\n",
				socket_path,
				strerror(errno));
			goto out;
		}
		printf("OK\n");
	} else if (cmd == UDBG_ENH_SERVER_CLI_CMD_START) {
		if (udbg_enh_server_ctrl_client_start(
			    &udbg_enh_server_ctrl_client_ctx,
			    capture_file_name,
			    capture_rules_file_name,
			    DEFAULT_STOP_TIMEOUT_MS) < 0) {
			fprintf(stderr, "START failed on '%s': %s\n",
				socket_path,
				strerror(errno));
			goto out;
		}
		printf("OK\n");
	} else {
		if (udbg_enh_server_ctrl_client_stop(
			    &udbg_enh_server_ctrl_client_ctx,
			    DEFAULT_STOP_TIMEOUT_MS) < 0) {
			fprintf(stderr, "STOP failed on '%s': %s\n",
				socket_path,
				strerror(errno));
			goto out;
		}
		printf("OK\n");
	}

	rc = 0;

out:
	udbg_enh_server_ctrl_client_close(&udbg_enh_server_ctrl_client_ctx);
	return rc;
}
