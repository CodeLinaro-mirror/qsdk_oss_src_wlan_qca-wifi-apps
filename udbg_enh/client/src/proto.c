/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "proto.h"

/*
 * udbg_client_core_proto_get_u32_le: Decodes a 32-bit little-endian integer.
 * @buf: Pointer to at least 4 bytes in little-endian order.
 *
 * @output: Returns decoded unsigned 32-bit value.
 */
static uint32_t udbg_client_core_proto_get_u32_le(const uint8_t *buf)
{
	return (uint32_t) buf[0] |
		((uint32_t) buf[1] << 8) |
		((uint32_t) buf[2] << 16) |
		((uint32_t) buf[3] << 24);
}

/*
 * udbg_client_core_proto_get_u64_le: Decodes a 64-bit little-endian integer.
 * @buf: Pointer to at least 8 bytes in little-endian order.
 *
 * @output: Returns decoded unsigned 64-bit value.
 */
static uint64_t udbg_client_core_proto_get_u64_le(const uint8_t *buf)
{
	return (uint64_t) udbg_client_core_proto_get_u32_le(buf) |
		((uint64_t) udbg_client_core_proto_get_u32_le(buf + 4) << 32);
}

/*
 * udbg_client_core_proto_put_u32_le: Encodes a 32-bit value in little-endian.
 * @buf: Output byte array with at least 4 writable bytes.
 * @v: Unsigned 32-bit value to encode.
 *
 * @output: No return value; writes 4 bytes into buf.
 */
static void udbg_client_core_proto_put_u32_le(uint8_t *buf, uint32_t v)
{
	buf[0] = (uint8_t) (v & 0xffu);
	buf[1] = (uint8_t) ((v >> 8) & 0xffu);
	buf[2] = (uint8_t) ((v >> 16) & 0xffu);
	buf[3] = (uint8_t) ((v >> 24) & 0xffu);
}

/*
 * udbg_client_core_proto_put_u64_le: Encodes a 64-bit value in little-endian.
 * @buf: Output byte array with at least 8 writable bytes.
 * @v: Unsigned 64-bit value to encode.
 *
 * @output: No return value; writes 8 bytes into buf.
 */
static void udbg_client_core_proto_put_u64_le(uint8_t *buf, uint64_t v)
{
	udbg_client_core_proto_put_u32_le(buf, (uint32_t) (v & 0xffffffffULL));
	udbg_client_core_proto_put_u32_le(buf + 4, (uint32_t) (v >> 32));
}

/*
 * udbg_client_core_proto_build_subscribe: Builds wire bytes for subscribe
 * request message.
 * @pinfo: Process identity and application info for subscribe payload.
 * @out: Output buffer where the wire message is written.
 * @out_cap: Capacity of the output buffer in bytes.
 * @out_len: Receives the encoded subscribe message length.
 *
 * @output: Returns 0 on success, or -1 if arguments/capacity are invalid.
 */
int udbg_client_core_proto_build_subscribe(
	const struct udbg_client_core_proto_process_info *pinfo,
	uint8_t *out, size_t out_cap, size_t *out_len)
{
	uint32_t wire_pid;
	size_t tx_len;

	if (!pinfo || !out || !out_len) {
		errno = EINVAL;
		return -1;
	}

	tx_len = UDBG_MSG_HEADER_SIZE + UDBG_MSG_SUBSCRIBE_REQ_SIZE;
	if (out_cap < tx_len) {
		errno = EMSGSIZE;
		return -1;
	}

	memset(out, 0, tx_len);
	udbg_client_core_proto_put_u64_le(out + UDBG_MSG_OFF_HANDLE, 0);
	udbg_client_core_proto_put_u32_le(out + UDBG_MSG_OFF_MSG_TYPE,
					  UDBG_SUBSCRIBE_REQ);
	udbg_client_core_proto_put_u64_le(out + UDBG_MSG_OFF_TIMESTAMP, 0);
	udbg_client_core_proto_put_u32_le(out + UDBG_MSG_OFF_LENGTH,
					  (uint32_t) tx_len);

	wire_pid = (uint32_t)
		(((uint64_t) (int64_t) pinfo->pid) & UDBG_EXT_WIRE_PID_MASK);
	udbg_client_core_proto_put_u32_le(out + UDBG_MSG_HEADER_SIZE, wire_pid);
	memcpy(out + UDBG_MSG_HEADER_SIZE + sizeof(uint32_t),
		  pinfo->uuid, sizeof(pinfo->uuid));
	memcpy(out + UDBG_MSG_HEADER_SIZE + sizeof(uint32_t) + sizeof(pinfo->uuid),
		  pinfo->app_id, sizeof(pinfo->app_id));

	*out_len = tx_len;
	return 0;
}

/*
 * udbg_client_core_proto_build_log: Builds wire bytes for a log record message.
 * @handle: Subscription handle placed in the message header.
 * @msg_type: Message type value written in the header.
 * @timestamp: Log timestamp in microseconds.
 * @payload: Pointer to payload bytes appended to the frame.
 * @payload_len: Number of payload bytes to encode.
 * @out: Output buffer where encoded message bytes are stored.
 * @out_cap: Capacity of the output buffer in bytes.
 * @out_len: Receives total encoded frame length.
 *
 * @output: Returns 0 on success, or -1 on validation/capacity failures.
 */
int udbg_client_core_proto_build_log(uint64_t handle, uint32_t msg_type,
	uint64_t timestamp, const void *payload, size_t payload_len,
	uint8_t *out, size_t out_cap, size_t *out_len)
{
	size_t tx_len;

	if (!out || !out_len || (payload_len && !payload)) {
		errno = EINVAL;
		return -1;
	}

	if (payload_len > (size_t) UINT32_MAX) {
		errno = EMSGSIZE;
		return -1;
	}
	if (payload_len > SIZE_MAX - UDBG_MSG_HEADER_SIZE - UDBG_MSG_LOG_PREFIX_SIZE) {
		errno = EMSGSIZE;
		return -1;
	}

	tx_len = UDBG_MSG_HEADER_SIZE + UDBG_MSG_LOG_PREFIX_SIZE + payload_len;
	if (out_cap < tx_len) {
		errno = EMSGSIZE;
		return -1;
	}

	memset(out, 0, tx_len);
	udbg_client_core_proto_put_u64_le(out + UDBG_MSG_OFF_HANDLE, handle);
	udbg_client_core_proto_put_u32_le(out + UDBG_MSG_OFF_MSG_TYPE, msg_type);
	udbg_client_core_proto_put_u64_le(out + UDBG_MSG_OFF_TIMESTAMP, timestamp);
	udbg_client_core_proto_put_u32_le(out + UDBG_MSG_OFF_LENGTH,
					  (uint32_t) tx_len);
	udbg_client_core_proto_put_u32_le(out + UDBG_MSG_HEADER_SIZE,
					  (uint32_t) payload_len);
	if (payload_len)
		memcpy(out + UDBG_MSG_HEADER_SIZE + UDBG_MSG_LOG_PREFIX_SIZE,
			  payload, payload_len);

	*out_len = tx_len;
	return 0;
}

/*
 * udbg_client_core_proto_parse: Parses received wire bytes into a structured
 * message view.
 * @buf: Raw input frame bytes to parse.
 * @len: Exact length of the received frame in bytes.
 * @msg: Output structure receiving parsed header/body fields.
 *
 * @output: Returns 0 on successful parse, or -1 when frame data is invalid.
 */
int udbg_client_core_proto_parse(const void *buf, size_t len,
	struct udbg_client_core_proto_parsed *msg)
{
	const uint8_t *bytes = buf;

	if (!bytes || !msg || len < UDBG_MSG_HEADER_SIZE) {
		errno = EINVAL;
		return -1;
	}

	memset(msg, 0, sizeof(*msg));
	msg->handle = udbg_client_core_proto_get_u64_le(bytes + UDBG_MSG_OFF_HANDLE);
	msg->msg_type = udbg_client_core_proto_get_u32_le(bytes + UDBG_MSG_OFF_MSG_TYPE);
	msg->timestamp = udbg_client_core_proto_get_u64_le(bytes + UDBG_MSG_OFF_TIMESTAMP);
	msg->length = udbg_client_core_proto_get_u32_le(bytes + UDBG_MSG_OFF_LENGTH);

	if (msg->length != (uint32_t) len) {
		errno = EINVAL;
		return -1;
	}

	switch (msg->msg_type) {
	case UDBG_SUBSCRIBE_RESP:
		if (len < UDBG_MSG_HEADER_SIZE + UDBG_MSG_SUBSCRIBE_RESP_SIZE) {
			errno = EMSGSIZE;
			return -1;
		}
		msg->has_subscribe_resp = 1;
		msg->subscribe_status = (int32_t)
			udbg_client_core_proto_get_u32_le(bytes + UDBG_MSG_HEADER_SIZE);
		break;
	default:
		break;
	}

	return 0;
}
