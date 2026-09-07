/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#ifndef SUBSYS_CORE_H
#define SUBSYS_CORE_H

#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include "hapd_log_listener.h"

#define SSH_MAX_ACTIONS_PER_ENUM 4
#define SSH_MAX_CTX_STRINGS 8
#define SS_SNAP_KEY_MINIDUMP  "minidump"
#define SS_SNAP_KEY_SYSLOG    "syslog"
extern volatile sig_atomic_t t_stop_flag;

enum subsys_action_id {
	SS_ACTION_ENABLE_DBG_LOGS = 0,
	SS_ACTION_INC_HAPD_VERBOSITY,
	SS_ACTION_SNAPSHOT,
	SS_ACTION_ENABLE_DBG_LOGS_ON_BOOT,
	SS_ACTION_HAPD_PEER_LOG,
	SS_ACTION_MAX
};

enum subsys_action_policy {
	SSH_ACTION_POLICY_EXTEND = 0,
	SSH_ACTION_POLICY_STOP_ON_REPRODUCE,
};

enum ath12k_crit_err_type {
	ATH12K_CRIT_VAP_BRINGUP = 0,
	ATH12K_CRIT_CONNECTION_FAIL = 1,
	ATH12K_CRIT_PEER_FAILURE = 2,
	ATH12K_FW_LOAD_FAILURE = 3,
	ATH12K_BDF_LOAD_FAILURE = 4,
	ATH12K_CRIT_MVR_FAILURE = 5,
	ATH12K_CRIT_SCAN_FAILURE = 6,
	ATH12K_CRIT_MAX
};

struct ath12k_crit_ring {
	uint32_t version;
	uint32_t count;
	uint32_t write_idx;
	uint32_t read_idx;
	uint32_t dropped;
	uint32_t flags;
} __attribute__((packed));

struct ath12k_crit_record {
	uint64_t ts_nsec;
	uint32_t trigger;
	uint16_t radio_id;
} __attribute__((packed));

struct crit_action_map {
	enum ath12k_crit_err_type trigger;
	enum subsys_action_policy policy;
	uint32_t num_actions;
	enum subsys_action_id actions[SSH_MAX_ACTIONS_PER_ENUM];
	char *action_context[SSH_MAX_ACTIONS_PER_ENUM][SSH_MAX_CTX_STRINGS];
};

struct subsys_trigger_state {
	enum ath12k_crit_err_type trigger_id;
	bool active;
	uint64_t window_end_ns;
	uint32_t trigger_count;
};

struct subsys_config {
	bool enable_crit_buffer;
	struct crit_action_map crit_maps[ATH12K_CRIT_MAX];
	uint32_t hapd_log_trigger_mask;
};

struct subsys_ctx {
	int crit_fd;
	struct ath12k_crit_ring *crit_ring;
	size_t crit_map_size;
	struct subsys_config cfg;
	pthread_mutex_t action_lock;
	struct subsys_trigger_state trigger_state[ATH12K_CRIT_MAX];
	struct hapd_listener_ctx hapd_log_ctx;
	bool hapd_log_active;
	uint64_t hapd_log_window_end_ns;
};

const char *ath12k_crit_type_str(enum ath12k_crit_err_type t);
void subsys_config_init_defaults(struct subsys_config *cfg);
const struct crit_action_map *find_map_for_enum(const struct subsys_config *cfg, enum ath12k_crit_err_type crit_err_enum);
int subsys_find_uio_dev(const char *wanted_name);
long subsys_uio_read_map_size(int uio_index);
void subsys_action_start(enum subsys_action_id act_id, uint16_t radio_id,
			 char * const *action_context,
			 enum ath12k_crit_err_type trigger);
void subsys_action_stop(enum subsys_action_id act_id, uint16_t radio_id, char * const* action_context,
			enum ath12k_crit_err_type trigger);
void subsys_uio_drain_crit_ring(struct subsys_ctx *ctx);
void subsys_update_action_windows(struct subsys_ctx *ctx);
void subsys_start_hapd_log_window(struct subsys_ctx *ctx);
void subsys_handle_crit_record(struct subsys_ctx *ctx, const struct ath12k_crit_record *rec);
void *subsys_critical_buffer_monitor_thread(void *arg);

void host_subsys_init_ctx(struct subsys_ctx *ctx);
void host_start_window_thread(struct subsys_ctx *ctx);

#endif /* SUBSYS_CORE_H */
