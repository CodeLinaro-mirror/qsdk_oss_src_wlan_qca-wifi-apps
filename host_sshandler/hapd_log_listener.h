/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#ifndef HAPD_LOG_LISTENER_H
#define HAPD_LOG_LISTENER_H

#include <stdint.h>
#include <sys/types.h>

#define HAPD_IFACE_LEN      32
/* Well-known socket path for direct hostapd -> sshandler notification.
 * hostapd sends a datagram here on every connection failure event;
 * sshandler binds and receives.  No ATTACH handshake required.
 *
 * Flow:
 *   hostapd                    host_sshandler
 *   --------                   --------------
 *   auth/assoc/4-way handshake failure
 *     |
 *     +--sendto(HAPD_SSH_SOCK_PATH)-->  listener thread
 *          "<event> <mac> <iface>"        |
 *                                         +-> validate input
 *                                         +-> LOG_LEVEL <mod> debug_verbose
 *                                         +-> LOG_PEER <mac>
 *                                         +-> peer_log_add(iface, mac)
 *
 *   dedicated hostapd log window expires (2 min):
 *     +-> hapd_log_listener_clear_all_peers()
 *           +-> LOG_LEVEL INFO
 *           +-> LOG_PEER clear
 */
#define HAPD_SSH_SOCK_PATH  "/var/run/host_sshandler.sock"

/* Wire format of each datagram (NUL-terminated string):
 *   "<event> <mac> <iface>"
 * e.g. "assoc_reject aa:bb:cc:dd:ee:ff phy00.1-0"
 *
 * Hostapd crash datagrams use a separate format because a fatal signal has
 * no BSS or station context:
 *   "hostapd_crash <pid> <signal> <executable>"
 * e.g. "hostapd_crash 1234 11 hostapd"
 */
#define HAPD_SSH_MSG_MAX    128
#define HAPD_CRASH_EVENT    "hostapd_crash"
#define HAPD_CRASH_EXE_LEN  32

struct hapd_crash_info {
	pid_t pid;
	int signal;
	char executable[HAPD_CRASH_EXE_LEN];
};

/* Trigger event type bitmasks for hapd_listener_ctx.trigger_mask.
 * 0 (HAPD_TRIG_ALL) enables all event types. */
#define HAPD_TRIG_AUTH_REJECT      (1U << 0)
#define HAPD_TRIG_ASSOC_REJECT     (1U << 1)
#define HAPD_TRIG_EAPOL_FAIL       (1U << 2)
#define HAPD_TRIG_VAP_CREATE_FAIL  (1U << 3)
#define HAPD_TRIG_VAP_UP_FAIL      (1U << 4)
#define HAPD_TRIG_AUTH_TX_FAIL     (1U << 5)
#define HAPD_TRIG_ASSOC_RESP_TX_FAIL (1U << 6)
#define HAPD_TRIG_REASSOC_RESP_TX_FAIL (1U << 7)
#define HAPD_TRIG_PROBE_RESP_TX_FAIL (1U << 8)
#define HAPD_TRIG_DEAUTH_TX_FAIL   (1U << 9)
#define HAPD_TRIG_DISASSOC_TX_FAIL (1U << 10)
#define HAPD_TRIG_ACTION_TX_FAIL   (1U << 11)
#define HAPD_TRIG_ALL              0U

struct hapd_listener_ctx {
	uint32_t trigger_mask; /* HAPD_TRIG_* bitmask; 0 = all enabled */
};

/* Thread entry point receives struct subsys_ctx * as arg.
 * The thread runs for the lifetime of the process, ready to receive
 * datagrams from hostapd at any time. */
void *subsys_hapd_listener_thread(void *arg);

/* Clear all active peer log filters and restore log levels when the
 * dedicated hostapd log window expires. */
void hapd_log_listener_clear_all_peers(void);

/* Start the hapd log listener thread. */
struct subsys_ctx;
void host_start_hapd_listener_thread(struct subsys_ctx *ctx);

#endif /* HAPD_LOG_LISTENER_H */
