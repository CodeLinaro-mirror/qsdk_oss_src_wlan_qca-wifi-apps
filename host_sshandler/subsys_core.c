/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <limits.h>
#include "subsys_core.h"
volatile sig_atomic_t t_stop_flag = 0;

const char *ath12k_crit_type_str(enum ath12k_crit_err_type t)
{
	switch (t) {
	case ATH12K_CRIT_VAP_BRINGUP:
		return "vap_bringup";
	case ATH12K_CRIT_CONNECTION_FAIL:
		return "connection_fail";
	case ATH12K_CRIT_PEER_FAILURE:
		return "peer_failure";
	case ATH12K_FW_LOAD_FAILURE:
		return "fw_load_failure";
	case ATH12K_BDF_LOAD_FAILURE:
		return "bdf_load_failure";
	case ATH12K_CRIT_MVR_FAILURE:
		return "mvr_failure";
	case ATH12K_CRIT_SCAN_FAILURE:
		return "scan_failure";
	default:
		return "host_unknown";
	}
}

static uint64_t get_monotonic_ns(void)
{
	struct timespec t_spec;
	clock_gettime(CLOCK_MONOTONIC, &t_spec);
	return (uint64_t)t_spec.tv_sec * 1000000000ULL + t_spec.tv_nsec;
}

void subsys_update_action_windows(struct subsys_ctx *ctx)
{
	uint64_t curr_time = get_monotonic_ns();
	struct subsys_trigger_state *trig_state;
	const struct crit_action_map *map;

	pthread_mutex_lock(&ctx->action_lock);

	for (int i = 0; i < ATH12K_CRIT_MAX; i++) {
		trig_state = &ctx->trigger_state[i];

		if (trig_state->active && curr_time >= trig_state->window_end_ns) {
			map = find_map_for_enum(&ctx->cfg, (enum ath12k_crit_err_type)i);

			if (map) {
				for (uint32_t k = 0; k < map->num_actions; k++) {
					subsys_action_stop(map->actions[k], USHRT_MAX, map->action_context[k]);
				}
			}
			trig_state->active = false;
		}
	}
	pthread_mutex_unlock(&ctx->action_lock);
}

static void subsys_start_and_update_trigger_window(struct subsys_ctx *ctx,
					const struct crit_action_map *map,
					uint64_t curr_time_ns,
					const struct ath12k_crit_record *rec)
{
	struct subsys_trigger_state *trig_state = &ctx->trigger_state[rec->trigger];
	const uint64_t delta = 2ULL * 60ULL * 1000000000ULL;

	if (!trig_state->active) {
		trig_state->trigger_id = rec->trigger;
		trig_state->active = true;
		trig_state->window_end_ns = curr_time_ns + delta;
		trig_state->trigger_count = 1;

		for (uint32_t i = 0; i < map->num_actions; i++) {
			subsys_action_start(map->actions[i], rec->radio_id,
					    map->action_context[i],
					    rec->trigger);
		}
		fprintf(stdout, "host-sshandler : Critical Error Actions triggered for  ath12k-crit-enum=%u.\n", rec->trigger);
		return;
	}

	if (map->policy == SSH_ACTION_POLICY_EXTEND) {
		trig_state->window_end_ns = curr_time_ns + delta;
		trig_state->trigger_count++;
	}
	else if (map->policy == SSH_ACTION_POLICY_STOP_ON_REPRODUCE) {
		fprintf(stdout, "host-sshandler : Critical Error Reproduced ath12k-crit-enum=%u.\n", rec->trigger);

		if (trig_state->trigger_count >= 1) {
			for (uint32_t i = 0; i < map->num_actions; i++) {
				subsys_action_stop(map->actions[i], rec->radio_id, map->action_context[i]);
			}
			trig_state->active = false;
		}
	}
}

void subsys_handle_crit_record(struct subsys_ctx *ctx, const struct ath12k_crit_record *rec)
{
	uint64_t curr_time = rec->ts_nsec;

	fprintf(stderr, "host-sshandler : ath12k-crit-enum=%u radio=%u\n",
			rec->trigger, rec->radio_id);

	pthread_mutex_lock(&ctx->action_lock);

	const struct crit_action_map *map = find_map_for_enum(&ctx->cfg, (enum ath12k_crit_err_type)rec->trigger);

	if (!map) {
		fprintf(stderr, "host-sshandler : No action map for enum=%u\n", rec->trigger);
		pthread_mutex_unlock(&ctx->action_lock);
		return;
	}

	subsys_start_and_update_trigger_window(ctx, map, curr_time, rec);

	pthread_mutex_unlock(&ctx->action_lock);
}

void *subsys_critical_buffer_monitor_thread(void *arg)
{
	struct subsys_ctx *ctx = arg;
	int uiofd = ctx->crit_fd;
	struct pollfd pfd = {.fd = uiofd, .events = POLLIN, .revents = 0};
	const int timeout_ms = 150000;
	int ret;

	while (!t_stop_flag) {
		ret = poll(&pfd, 1, timeout_ms);
		if (t_stop_flag)
			break;

		if (ret >= 0) {
			if (ret > 0 && (pfd.revents & POLLIN)) {
				uint32_t irq_count;

				if (read(uiofd, &irq_count, sizeof(irq_count)) == sizeof(irq_count)) {
					fprintf(stdout, "host-sshandler : Read successful\n");
				}
			}
			subsys_uio_drain_crit_ring(ctx);
		}
		else if (errno != EINTR) {
			fprintf(stderr, "host-sshandler : Poll failed: %s\n", strerror(errno));
			sleep(1);
		}
	}
	return NULL;
}
