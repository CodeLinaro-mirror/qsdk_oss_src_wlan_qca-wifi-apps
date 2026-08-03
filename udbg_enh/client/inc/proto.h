/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef PROTO_H
#define PROTO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifndef STRUCT_PACKED
#define STRUCT_PACKED __attribute__ ((packed))
#endif

#define UDBG_EXT_MSG_BASE_MASK 0xFFFF0000u
#define UDBG_EXT_MSG_SUBTYPE_MASK 0x0000FFFFu
#define UDBG_EXT_MSG_BASE(msg_type) \
	((uint32_t)((msg_type) & UDBG_EXT_MSG_BASE_MASK))
#define UDBG_EXT_MSG_SUBTYPE(msg_type) \
	((uint32_t)((msg_type) & UDBG_EXT_MSG_SUBTYPE_MASK))
#define UDBG_EXT_MSG_TYPE(base, subtype) \
	(((uint32_t)(base) & UDBG_EXT_MSG_BASE_MASK) | \
	 ((uint32_t)(subtype) & UDBG_EXT_MSG_SUBTYPE_MASK))

#define UDBG_EXT_CTRL_CMD_BASE 0x11110000u
#define UDBG_EXT_DATA_CMD_BASE 0x10000000u

#define UDBG_EXT_CTRL_SUBSCRIBE_REQ  0x0001u
#define UDBG_EXT_CTRL_SUBSCRIBE_RESP 0x0002u

#define UDBG_EXT_DATA_NL_TX 0x0001u
#define UDBG_EXT_DATA_NL_RX 0x0002u
#define UDBG_EXT_DATA_LOG    0x0003u
#define UDBG_EXT_DATA_NL_RX_NCTRL_NL80211 0x0004u

#define UDBG_SUBSCRIBE_REQ \
	UDBG_EXT_MSG_TYPE(UDBG_EXT_CTRL_CMD_BASE, \
			  UDBG_EXT_CTRL_SUBSCRIBE_REQ)
#define UDBG_SUBSCRIBE_RESP \
	UDBG_EXT_MSG_TYPE(UDBG_EXT_CTRL_CMD_BASE, \
			  UDBG_EXT_CTRL_SUBSCRIBE_RESP)
#define UDBG_NL_TX \
	UDBG_EXT_MSG_TYPE(UDBG_EXT_DATA_CMD_BASE, \
			  UDBG_EXT_DATA_NL_TX)
#define UDBG_NL_RX \
	UDBG_EXT_MSG_TYPE(UDBG_EXT_DATA_CMD_BASE, \
			  UDBG_EXT_DATA_NL_RX)
#define UDBG_LOG \
	UDBG_EXT_MSG_TYPE(UDBG_EXT_DATA_CMD_BASE, \
			  UDBG_EXT_DATA_LOG)
#define UDBG_NLCTRL_NL80211 \
	UDBG_EXT_MSG_TYPE(UDBG_EXT_DATA_CMD_BASE, \
	                          UDBG_EXT_DATA_NL_RX_NCTRL_NL80211)

#define UDBG_EXT_WIRE_PID_MASK UINT32_C(0xFFFFFFFF)
#define UDBG_CLIENT_CORE_UUID_SIZE 16u
#define UDBG_CLIENT_CORE_APP_ID_SIZE 64u

struct udbg_client_core_proto_msg {
	uint64_t handle;
	uint32_t msg_type;
	uint64_t timestamp;
	uint32_t length;

	union {
		struct {
			uint32_t pid;
			uint8_t uuid[UDBG_CLIENT_CORE_UUID_SIZE];
			char app_id[UDBG_CLIENT_CORE_APP_ID_SIZE];
		} STRUCT_PACKED subscribe_req;

		struct {
			int32_t status;
		} STRUCT_PACKED subscribe_resp;

		struct {
			uint32_t payload_len;
			uint8_t payload[];
		} STRUCT_PACKED log;
	} u;
} STRUCT_PACKED;

#define UDBG_MSG_HEADER_SIZE \
	((size_t) offsetof(struct udbg_client_core_proto_msg, u))
#define UDBG_MSG_SUBSCRIBE_REQ_SIZE \
	((size_t) sizeof(((struct udbg_client_core_proto_msg *) 0)->u.subscribe_req))
#define UDBG_MSG_SUBSCRIBE_RESP_SIZE \
	((size_t) sizeof(((struct udbg_client_core_proto_msg *) 0)->u.subscribe_resp))
#define UDBG_MSG_LOG_PREFIX_SIZE \
	((size_t) sizeof(((struct udbg_client_core_proto_msg *) 0)->u.log.payload_len))

#define UDBG_MSG_OFF_HANDLE 0u
#define UDBG_MSG_OFF_MSG_TYPE 8u
#define UDBG_MSG_OFF_TIMESTAMP 12u
#define UDBG_MSG_OFF_LENGTH 20u

struct udbg_client_core_proto_process_info {
	pid_t pid;
	uint8_t uuid[UDBG_CLIENT_CORE_UUID_SIZE];
	char app_id[UDBG_CLIENT_CORE_APP_ID_SIZE];
};

struct udbg_client_core_proto_parsed {
	uint64_t handle;
	uint32_t msg_type;
	uint64_t timestamp;
	uint32_t length;
	int has_subscribe_resp;
	int32_t subscribe_status;
};

// Builds a subscribe request frame.
int udbg_client_core_proto_build_subscribe(
	const struct udbg_client_core_proto_process_info *pinfo,
	uint8_t *out, size_t out_cap, size_t *out_len);

// Builds a log frame.
int udbg_client_core_proto_build_log(uint64_t handle, uint32_t msg_type,
	uint64_t timestamp, const void *payload, size_t payload_len,
	uint8_t *out, size_t out_cap, size_t *out_len);

// Parses a wire frame into structured fields.
int udbg_client_core_proto_parse(const void *buf, size_t len,
	struct udbg_client_core_proto_parsed *msg);

#endif /* PROTO_H */
