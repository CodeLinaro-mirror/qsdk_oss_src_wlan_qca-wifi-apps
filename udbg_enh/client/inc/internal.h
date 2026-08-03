/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef INTERNAL_H
#define INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "core.h"
#include "nlctrl_nl80211.h"

// Subscription protocol state; retry/wait orchestration is tracked by step type.
enum udbg_client_core_subscription_state {
	UDBG_CLIENT_CORE_SUBSCRIPTION_IDLE = 0,
	UDBG_CLIENT_CORE_SUBSCRIPTION_WAIT_SUBSCRIBE_ACK,
	UDBG_CLIENT_CORE_SUBSCRIPTION_READY
};

struct udbg_client_core_buffer_record {
	uint32_t msg_type;
	uint64_t timestamp;
	uint64_t seqno;
	size_t payload_len;
	uint8_t *payload;
};

struct udbg_client_core_buffer {
	struct udbg_client_core_buffer_record *ring; // Allocated ring storage for queued records.
	size_t capacity; // Total slots available in the ring.
	size_t count; // Number of records currently queued.
	size_t head; // Index of the oldest record.
	size_t tail; // Index where the next record will be inserted.
	size_t bytes; // Sum of payload bytes currently buffered.
	size_t max_bytes; // Maximum allowed buffered payload bytes.
	uint64_t next_seq; // Monotonic sequence generator for enqueue order.
};

enum udbg_client_core_connect_outcome {
	UDBG_CLIENT_CORE_CONNECT_OK = 0,
	UDBG_CLIENT_CORE_CONNECT_RETRYABLE_FAIL,
	UDBG_CLIENT_CORE_CONNECT_PERMANENT_FAIL
};

enum udbg_client_core_step_type {
	UDBG_CLIENT_CORE_STEP_NONE = 0,
	UDBG_CLIENT_CORE_STEP_CONNECT,
	UDBG_CLIENT_CORE_STEP_SEND_SUBSCRIBE,
	UDBG_CLIENT_CORE_STEP_WAIT,
	UDBG_CLIENT_CORE_STEP_STOP_PERMANENT
};

struct udbg_client_core_state {
	char server_ip[UDBG_CLIENT_CORE_SERVER_IP_SIZE];
	int server_port;
	struct udbg_client_core_proto_process_info proto_process_info;
	struct udbg_client_core_buffer buffer;

	int sock_fd;
	uint64_t subscribe_handle;
	enum udbg_client_core_subscription_state subscription_state;

	enum udbg_client_core_step_type pending_step;

	struct udbg_client_core_nlctrl_nl80211_buffer nlctrl_nl80211_buffer;
};

// Initializes queue storage for buffered logs.
int udbg_client_core_buffer_init(struct udbg_client_core_buffer *buffer,
	size_t capacity, size_t max_bytes);

// Releases queue storage and queued payloads.
void udbg_client_core_buffer_deinit(struct udbg_client_core_buffer *buffer);

// Adds a log payload record to the queue.
int udbg_client_core_buffer_enqueue(struct udbg_client_core_buffer *buffer,
	uint32_t msg_type, const void *payload, size_t payload_len,
	uint64_t timestamp);

// Returns the current head record without removing it.
const struct udbg_client_core_buffer_record *
udbg_client_core_buffer_peek(const struct udbg_client_core_buffer *buffer);

// Removes the current head record.
void udbg_client_core_buffer_pop(struct udbg_client_core_buffer *buffer);

// Queues one log payload.
int udbg_client_core_queue_log(struct udbg_client_core_buffer *buffer,
	uint32_t msg_type, const void *payload, size_t payload_len);

// Returns the wire length for the next queued record.
size_t udbg_client_core_next_queued_wire_len(
	const struct udbg_client_core_buffer *buffer);

// Builds the next queued record into a log frame.
int udbg_client_core_build_next_queued_log(
	const struct udbg_client_core_buffer *buffer, uint64_t subscribe_handle,
	uint8_t *out, size_t out_cap, size_t *out_len);

// Loads or generates the client UUID used in subscribe identity.
int udbg_client_core_uuid_random(uint8_t uuid[UDBG_CLIENT_CORE_UUID_SIZE]);

// Reads current wall-clock time in microseconds.
uint64_t udbg_client_core_timestamp_us(void);

#endif /* INTERNAL_H */
