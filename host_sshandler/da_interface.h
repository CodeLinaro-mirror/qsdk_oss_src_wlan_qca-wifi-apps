// SPDX-License-Identifier: ISC
/* Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.*/

#ifndef HOSTSUBSYSTEM_HANDLER_H
#define HOSTSUBSYSTEM_HANDLER_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include "transport_client.h"
#include "debug_agent.h"

#define PAYLOAD_SIZE  1020
#define HOST_UIO_ID   1
#define MAX_CMD_LEN   512

void da_interface_host_create_snapshot(const char *event_name);
#endif /* HOST_SUBSYSTEMHANDLER_H */
