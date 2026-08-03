// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef SERVER_CTRL_SOCKET_H
#define SERVER_CTRL_SOCKET_H

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#define UDBG_ENH_SERVER_CTRL_CMD_PING_STR "PING"
#define UDBG_ENH_SERVER_CTRL_CMD_TERMINATE_STR "TERMINATE"
#define UDBG_ENH_SERVER_CTRL_CMD_FLUSH_STR "FLUSH"
#define UDBG_ENH_SERVER_CTRL_CMD_START_STR "START"
#define UDBG_ENH_SERVER_CTRL_CMD_STOP_STR "STOP"

#define UDBG_ENH_SERVER_CTRL_REPLY_PONG_STR "PONG\n"
#define UDBG_ENH_SERVER_CTRL_REPLY_OK_STR "OK\n"
#define UDBG_ENH_SERVER_CTRL_REPLY_FAIL_STR "FAIL\n"

struct udbg_enh_server_ctrl_socket {
	int fd;
	char *path;
};

enum udbg_enh_server_ctrl_command {
	UDBG_ENH_SERVER_CTRL_CMD_INVALID = 0,
	UDBG_ENH_SERVER_CTRL_CMD_PING = 1,
	UDBG_ENH_SERVER_CTRL_CMD_TERMINATE = 2,
	UDBG_ENH_SERVER_CTRL_CMD_FLUSH = 3,
	UDBG_ENH_SERVER_CTRL_CMD_START = 4,
	UDBG_ENH_SERVER_CTRL_CMD_STOP = 5,
};

enum udbg_enh_server_cli_command {
	UDBG_ENH_SERVER_CLI_CMD_INVALID = 0,
	UDBG_ENH_SERVER_CLI_CMD_PING = 1,
	UDBG_ENH_SERVER_CLI_CMD_TERMINATE = 2,
	UDBG_ENH_SERVER_CLI_CMD_FLUSH = 3,
	UDBG_ENH_SERVER_CLI_CMD_START = 4,
	UDBG_ENH_SERVER_CLI_CMD_STOP = 5,
};

int udbg_enh_server_ctrl_socket_open(struct udbg_enh_server_ctrl_socket *ctx,
					     const char *path);
void udbg_enh_server_ctrl_socket_close(struct udbg_enh_server_ctrl_socket *ctx);
int udbg_enh_server_ctrl_socket_get_fd(const struct udbg_enh_server_ctrl_socket *ctx);
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
					   socklen_t *stop_peer_len);
int udbg_enh_server_ctrl_socket_reply(int fd,
				      const struct sockaddr_un *peer,
				      socklen_t peer_len,
				      const char *reply);

#endif /* SERVER_CTRL_SOCKET_H */
