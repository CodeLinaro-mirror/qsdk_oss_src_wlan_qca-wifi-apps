/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#ifndef HAPD_LOG_LISTENER_H
#define HAPD_LOG_LISTENER_H

#include <stdint.h>

#define HAPD_IFACE_LEN      32
/* Well-known socket path for direct hostapd -> sshandler notification.
 * hostapd sends a datagram here on every connection failure event;
 * sshandler binds and receives.  No ATTACH handshake required.
 *
 * Flow:
 *   hostapd                    host_sshandler
 *   --------                   --------------
 *   auth/assoc/eapol failure
 *     |
 *     +--sendto(HAPD_SSH_SOCK_PATH)-->  listener thread
 *          "<event> <mac> <iface>"        |
 *                                         +-> validate input
 *                                         +-> LOG_LEVEL <mod> debug_verbose
 *                                         +-> LOG_PEER <mac>
 *                                         +-> peer_log_add(iface, mac)
 *
 *   subsys action window expires (2 min, managed by ss_handler core):
 *     SS_ACTION_HAPD_PEER_LOG stop
 *       +-> hapd_log_listener_clear_all_peers()
 *             +-> LOG_LEVEL <mod> default   (restore per-module level)
 *             +-> LOG_PEER clear            (clear peer filter + dedup)
 */
#define HAPD_SSH_SOCK_PATH  "/var/run/host_sshandler.sock"

/* Wire format of each datagram (NUL-terminated string):
 *   "<event> <mac> <iface>"
 * e.g. "assoc_reject aa:bb:cc:dd:ee:ff phy00.1-0"
 */
#define HAPD_SSH_MSG_MAX    128

/* Trigger event type bitmasks for hapd_listener_ctx.trigger_mask.
 * 0 (HAPD_TRIG_ALL) enables all event types. */
#define HAPD_TRIG_AUTH_REJECT   (1U << 0)
#define HAPD_TRIG_ASSOC_REJECT  (1U << 1)
#define HAPD_TRIG_EAPOL_FAIL    (1U << 2)
#define HAPD_TRIG_ALL           0U

struct hapd_listener_ctx {
	uint32_t trigger_mask; /* HAPD_TRIG_* bitmask; 0 = all enabled */
};

/* Thread entry point — pass struct hapd_listener_ctx * as arg.
 * The thread runs for the lifetime of the process, ready to receive
 * datagrams from hostapd at any time. */
void *subsys_hapd_listener_thread(void *arg);

/* Clear all active peer log filters and restore module log levels.
 * Called by SS_ACTION_HAPD_PEER_LOG stop when the subsys action window
 * expires.  The 2-minute window is managed by ss_handler core, not the
 * listener itself. */
void hapd_log_listener_clear_all_peers(void);

/* Start the hapd log listener thread. */
struct subsys_ctx;
void host_start_hapd_listener_thread(struct subsys_ctx *ctx);

#endif /* HAPD_LOG_LISTENER_H */
