/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef CORE_H
#define CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "proto.h"

extern void (*udbg_client_core_schedule_service_fn)(void);
extern void (*udbg_client_core_permanent_stop_fn)(void);

#define UDBG_CLIENT_CORE_BUFFER_DEFAULT_CAPACITY 512
#define UDBG_CLIENT_CORE_BUFFER_DEFAULT_MAX_BYTES (2 * 1024 * 1024)
#define UDBG_CLIENT_CORE_BUFFER_MAX_CAPACITY 65536
#define UDBG_CLIENT_CORE_BUFFER_MAX_BYTES_LIMIT (64 * 1024 * 1024)
#define UDBG_CLIENT_CORE_SERVER_IP_SIZE 46u
#define UDBG_CLIENT_CORE_SERVER_IP "127.0.0.1"
#define UDBG_CLIENT_CORE_SERVER_PORT 55555
#define UDBG_CLIENT_CORE_CLIENT_APP_ID "app"

// Initializes the single client core instance.
int udbg_client_core_init(const char *server_ip, int server_port, const char *app_id,
	size_t buffer_capacity, size_t buffer_max_bytes);

// Releases all resources owned by the client core instance.
void udbg_client_core_deinit(void);

// Queues one data-log payload and flushes queue when transport state allows.
void udbg_client_core_send_log(uint32_t msg_type, const void *payload,
	size_t payload_len);

// Drains socket input and executes pending core steps; service_timer_fired
// indicates that the previously scheduled service delay elapsed.
void udbg_client_core_service(bool service_timer_fired);

// Closes transport and resets subscription-process state.
void udbg_client_core_disconnect(void);

#endif /* CORE_H */
