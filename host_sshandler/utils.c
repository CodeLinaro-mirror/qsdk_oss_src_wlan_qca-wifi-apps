/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include "subsys_core.h"

#define SUBSYS_NUM_MAP_ENTRIES(map) (sizeof(map) / sizeof(map[0]))

static const struct crit_action_map subsys_default_map[] = {
	{
		ATH12K_CRIT_VAP_BRINGUP,
		SSH_ACTION_POLICY_STOP_ON_REPRODUCE,
		1,
		{SS_ACTION_ENABLE_DBG_LOGS},
		{ {"wmi", "mac", "peer"} }
	},
	{
		ATH12K_CRIT_CONNECTION_FAIL,
		SSH_ACTION_POLICY_STOP_ON_REPRODUCE,
		1,
		{SS_ACTION_ENABLE_DBG_LOGS},
		{ {"peer"} }
	}
};

void subsys_config_init_defaults(struct subsys_config *cfg)
{
	int num_defaults = SUBSYS_NUM_MAP_ENTRIES(subsys_default_map);
	const struct crit_action_map *entry;
	cfg->enable_crit_buffer = true;
	int i;

	for (i = 0; i < num_defaults; i++) {
		entry = &subsys_default_map[i];

		if (entry->trigger >= ATH12K_CRIT_MAX)
			continue;

		memcpy(&cfg->crit_maps[entry->trigger], entry, sizeof(*entry));
	}
}

const struct crit_action_map * find_map_for_enum(const struct subsys_config *cfg,
						enum ath12k_crit_err_type crit_err_enum)
{
	if (crit_err_enum < 0 || crit_err_enum >= ATH12K_CRIT_MAX) {
		fprintf(stderr, "host-sshandler : No action map found for this critical error\n");
		return NULL;
	}
	return &cfg->crit_maps[crit_err_enum];
}

void host_subsys_init_ctx(struct subsys_ctx *ctx)
{
	int i;

	memset(ctx, 0, sizeof(*ctx));

	subsys_config_init_defaults(&ctx->cfg);
	pthread_mutex_init(&ctx->action_lock, NULL);

	for (i = 0; i < ATH12K_CRIT_MAX; i++) {
		ctx->trigger_state[i].trigger_id = (enum ath12k_crit_err_type)i;
		ctx->trigger_state[i].active = false;
		ctx->trigger_state[i].window_end_ns = 0;
		ctx->trigger_state[i].trigger_count = 0;
	}
}
