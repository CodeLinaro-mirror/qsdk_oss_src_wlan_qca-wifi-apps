// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef NET_H
#define NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef STRUCT_PACKED
#define STRUCT_PACKED __attribute__ ((packed))
#endif

typedef enum {
	UDBG_ENH_TRANSPORT_UNDEFINED = 0,
	UDBG_ENH_TRANSPORT_TCP = SOCK_STREAM,
	UDBG_ENH_TRANSPORT_UDP = SOCK_DGRAM,
} udbg_enh_transport_t;

/*
 * Message type layout:
 * - upper 16 bits: base
 * - lower 16 bits: subtype
 */
#define UDBG_ENH_MSG_BASE_MASK 0xFFFF0000u
#define UDBG_ENH_MSG_SUBTYPE_MASK 0x0000FFFFu
#define UDBG_ENH_MSG_BASE(msg_type) \
	((uint32_t)((msg_type) & UDBG_ENH_MSG_BASE_MASK))
#define UDBG_ENH_MSG_SUBTYPE(msg_type) \
	((uint32_t)((msg_type) & UDBG_ENH_MSG_SUBTYPE_MASK))
#define UDBG_ENH_MSG_TYPE(base, subtype) \
	(((uint32_t)(base) & UDBG_ENH_MSG_BASE_MASK) | \
	 ((uint32_t)(subtype) & UDBG_ENH_MSG_SUBTYPE_MASK))

#define UDBG_ENH_CTRL_CMD_BASE 0x11110000u
#define UDBG_ENH_DATA_CMD_BASE 0x10000000u

#define UDBG_ENH_CTRL_SUBSCRIBE_REQ  0x0001u
#define UDBG_ENH_CTRL_SUBSCRIBE_RESP 0x0002u

#define UDBG_ENH_DATA_NL_TX 0x0001u
#define UDBG_ENH_DATA_NL_RX 0x0002u
#define UDBG_ENH_DATA_LOG    0x0003u
#define UDBG_ENH_DATA_NL_RX_NCTRL_NL80211 0x0004u

#define UDBG_SUBSCRIBE_REQ \
	UDBG_ENH_MSG_TYPE(UDBG_ENH_CTRL_CMD_BASE, \
			    UDBG_ENH_CTRL_SUBSCRIBE_REQ)
#define UDBG_SUBSCRIBE_RESP \
	UDBG_ENH_MSG_TYPE(UDBG_ENH_CTRL_CMD_BASE, \
			    UDBG_ENH_CTRL_SUBSCRIBE_RESP)
#define UDBG_NL_TX \
	UDBG_ENH_MSG_TYPE(UDBG_ENH_DATA_CMD_BASE, \
			    UDBG_ENH_DATA_NL_TX)
#define UDBG_NL_RX \
	UDBG_ENH_MSG_TYPE(UDBG_ENH_DATA_CMD_BASE, \
			    UDBG_ENH_DATA_NL_RX)
#define UDBG_LOG \
	UDBG_ENH_MSG_TYPE(UDBG_ENH_DATA_CMD_BASE, \
			    UDBG_ENH_DATA_LOG)
#define UDBG_NLCTRL_NL80211 \
        UDBG_ENH_MSG_TYPE(UDBG_ENH_DATA_CMD_BASE, \
                                  UDBG_ENH_DATA_NL_RX_NCTRL_NL80211)

/* Fixed-size wire PID representation for on-network messages. */
#define UDBG_ENH_WIRE_PID_MASK UINT32_C(0xFFFFFFFF)
#define UDBG_ENH_UUID_SIZE 16u
#define UDBG_ENH_APP_ID_SIZE 64u
#define UDBG_ENH_SERVER_IP_SIZE INET6_ADDRSTRLEN

struct debug_msg {
	uint64_t handle;
	uint32_t msg_type;
	uint64_t timestamp;
	uint32_t length;

	union {
		struct {
			uint32_t pid;
			uint8_t uuid[UDBG_ENH_UUID_SIZE];
			char app_id[UDBG_ENH_APP_ID_SIZE];
		} STRUCT_PACKED subscribe_req;

		struct {
			int32_t status; /* Success = 1*/
		} STRUCT_PACKED subscribe_resp;

		struct {
			uint32_t payload_len;
			uint8_t payload[];
		} STRUCT_PACKED log;
	} u;
} STRUCT_PACKED;

#define DEBUG_MSG_HEADER_SIZE ((size_t)offsetof(struct debug_msg, u))
#define DEBUG_MSG_SUBSCRIBE_REQ_SIZE \
	((size_t)sizeof(((struct debug_msg *)0)->u.subscribe_req))
#define DEBUG_MSG_SUBSCRIBE_RESP_SIZE \
	((size_t)sizeof(((struct debug_msg *)0)->u.subscribe_resp))

#define DEBUG_MSG_OFF_HANDLE 0u
#define DEBUG_MSG_OFF_MSG_TYPE 8u
#define DEBUG_MSG_OFF_TIMESTAMP 12u
#define DEBUG_MSG_OFF_LENGTH 20u

#define UDBG_ENH_MAX_MSG_SIZE 4096u
#define UDBG_ENH_UDP_BATCH_SIZE_MAX 512u
#define UDBG_ENH_UDP_BATCH_SIZE_DEFAULT 64u

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

struct udbg_enh_config {
	char server_ip[UDBG_ENH_SERVER_IP_SIZE];
	uint16_t server_port;
	uint32_t server_max_subscriptions;
	uint32_t server_max_log_entries;
	uint32_t stop_timeout_ms;
	uint32_t stop_poll_us;
	uint32_t liveness_check_interval_ms;
	uint32_t stale_timeout_ms;
	udbg_enh_transport_t transport;
	int udp_batch_enable;
	uint32_t udp_batch_size;
	uint32_t udp_batch_budget_us;
};

struct udbg_enh_process_info {
	pid_t pid;
	uint8_t uuid[UDBG_ENH_UUID_SIZE];
	char app_id[UDBG_ENH_APP_ID_SIZE];
};

struct udbg_enh_client_info {
	int fd;
	uint64_t handle;
	struct sockaddr_in addr;
	int active;
	uint64_t last_seen_us;
	struct udbg_enh_process_info pid_info;
	struct debug_msg *nlctrl_nl80211_msg;
};

struct udbg_enh_subscription_table {
	struct udbg_enh_client_info *clients;
	size_t capacity;
	size_t nclients;
	size_t head;
	bool table_full;
};

int udbg_enh_load_config(const char *path, struct udbg_enh_config *cfg);
void udbg_enh_config_deinit(struct udbg_enh_config *cfg);

void udbg_enh_server_run(const struct udbg_enh_config *cfg,
			 const char *capture_rules_path,
			 const char *control_socket_path,
			 const char *startup_capture_path);

#endif /* NET_H */
