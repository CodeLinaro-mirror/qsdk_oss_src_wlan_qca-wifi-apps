/* Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>
#include <dirent.h>
#include <pthread.h>
#include "subsys_core.h"
#include "da_interface.h"

#define ATH12K_DEBUGFS_ROOT "/sys/kernel/debug/ath12k"
#define ATH12K_ATH_DEBUG_DIR "ath_debug"
#define ATH12K_DBGMASK_FILE "dbgmask"
#define DBGMASK_PREFIX "Current: "
#define MAX_PATH_LEN 512
#define MAX_MASK_BUF_LEN 512
#define ATH12K_MINIDUMP_DIR_NAME "minidump"
#define ATH12K_MINIDUMP_COLLECT "collect"
#define TEMP_DIR "/tmp"
#define LOGREAD_CMD          "logread"
#define MINIDUMP_DIR    TEMP_DIR "/minidump"
#define HOST_DEBUG_DIR  TEMP_DIR "/host_debug_logs"
#define ATH12K_SNAPSHOT_FILE  "snapshot"

static int ath12k_get_dbgmask_path(char *path_buf, size_t buf_size)
{
	DIR *dir;
	struct dirent *entry;
	int ret = -ENOENT;

	if (!path_buf || buf_size == 0)
		return -EINVAL;

	dir = opendir(ATH12K_DEBUGFS_ROOT);
	if (!dir) {
		fprintf(stderr, "host-sshandler: Failed to open %s: %s\n",
			ATH12K_DEBUGFS_ROOT, strerror(errno));
		return -errno;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(path_buf, buf_size, "%s/%s/%s/%s",
			ATH12K_DEBUGFS_ROOT, entry->d_name,
			ATH12K_ATH_DEBUG_DIR, ATH12K_DBGMASK_FILE);

	if (access(path_buf, F_OK) == 0) {
			ret = 0;
			break;
		}
	}

	closedir(dir);
	return ret;
}

static int ath12k_read_current_mask(const char *path, char *buf, size_t size)
{
	FILE *fp;
	char line[MAX_MASK_BUF_LEN];
	int ret = -EIO;

	fp = fopen(path, "r");
	if (!fp)
		return -errno;

	buf[0] = '\0';

	while (fgets(line, sizeof(line), fp)) {
		char *prefix = strstr(line, DBGMASK_PREFIX);
		if (prefix) {
		char *newline;
		char *mask_str = prefix + strlen(DBGMASK_PREFIX);

		newline = strchr(mask_str, '\n');
		if (newline)
			*newline = '\0';

		snprintf(buf, size, "%s", mask_str);
		ret = 0;
		break;
		}
	}

	fclose(fp);
	return ret;
}

static void ath12k_update_mask_buffer(const char *current, const char *target,
				bool enable, char *out_buf, size_t out_size)
{
	char temp[MAX_MASK_BUF_LEN];
	char *token;
	char *saveptr;
	bool first = true;
	bool exists = false;

	snprintf(temp, sizeof(temp), "%s", current);

	out_buf[0] = '\0';

	token = strtok_r(temp, ":", &saveptr);
	while (token) {
		if (strcmp(token, target) == 0) {
			exists = true;
			if (!enable) {
				token = strtok_r(NULL, ":", &saveptr);
				continue;
			}
		}

		if (!first) {
			strlcat(out_buf, ":", out_size);
		}

		strlcat(out_buf, token, out_size);
		first = false;
		token = strtok_r(NULL, ":", &saveptr);
	}

	if (enable && !exists) {
		if (!first) {
			strlcat(out_buf, ":", out_size);
		}
		strlcat(out_buf, target, out_size);
	}
}

int ath12k_debug_set_mask_str(const char *mask_name, bool enable)
{
	char path[MAX_PATH_LEN];
	char current_mask[MAX_MASK_BUF_LEN];
	char new_mask[MAX_MASK_BUF_LEN];
	FILE *fp;
	int ret;

	if (!mask_name)
		return -EINVAL;

	ret = ath12k_get_dbgmask_path(path, sizeof(path));
	if (ret < 0)
		return ret;

	ret = ath12k_read_current_mask(path, current_mask, sizeof(current_mask));
	if (ret < 0) {
		current_mask[0] = '\0';
	}

	ath12k_update_mask_buffer(current_mask, mask_name, enable, new_mask, sizeof(new_mask));

	if (strcmp(current_mask, new_mask) == 0) {
		return 0;
	}

	fp = fopen(path, "w");
	if (!fp) {
		fprintf(stderr, "host-sshandler: Failed to open %s for write: %s\n",
			path, strerror(errno));
		return -errno;
	}

	fprintf(stderr, "host-sshandler: Updating debug mask: '%s' -> '%s'\n",
		current_mask, new_mask);

	if (fprintf(fp, "%s\n", new_mask) < 0)
		ret = -EIO;
	else
		ret = 0;

	fclose(fp);
	return ret;
}

static void subsys_process_debug_masks(char * const * action_context, bool enable)
{
	int i = 0;
	if (!action_context)
		return;

	while (i < SSH_MAX_CTX_STRINGS && action_context[i] != NULL) {
		ath12k_debug_set_mask_str(action_context[i], enable);
		i++;
	}
}

static void enable_hapd_verbose_logs(uint16_t radio_id)
{
	fprintf(stderr, "action: enable_hapd_verbose_logs (radio=%u)\n", radio_id);
}

static void disable_hapd_verbose_logs(uint16_t radio_id)
{
	fprintf(stderr, "action: disable_hapd_verbose_logs (radio=%u)\n", radio_id);
}

static int ath12k_get_minidump_path(char *path_buf)
{
	DIR *dir;
	struct dirent *entry;
	int ret = -ENOENT;

	dir = opendir(ATH12K_DEBUGFS_ROOT);
	if (!dir) {
		fprintf(stderr, "host-sshandler: Failed to open %s: %s\n",
			ATH12K_DEBUGFS_ROOT, strerror(errno));
		return -errno;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(path_buf, MAX_PATH_LEN, "%s/%s/%s/%s/%s",
			 ATH12K_DEBUGFS_ROOT, entry->d_name,
			 ATH12K_ATH_DEBUG_DIR, ATH12K_MINIDUMP_DIR_NAME,
			 ATH12K_MINIDUMP_COLLECT);

		if (access(path_buf, F_OK) == 0) {
			ret = 0;
			break;
		}
	}

	closedir(dir);
	return ret;
}

static void trigger_minidump(void)
{
	char minidump_path[MAX_PATH_LEN];
	FILE *fp;
	int ret;

	ret = ath12k_get_minidump_path(minidump_path);
	if (ret < 0) {
		fprintf(stderr, "host-sshandler: Cannot find minidump path\n");
		return;
	}

	fp = fopen(minidump_path, "w");
	if (!fp) {
		fprintf(stderr, "host-sshandler: Cannot open minidump trigger %s: %s\n",
			minidump_path, strerror(errno));
		return;
	}

	if (fprintf(fp, "1\n") < 0)
		fprintf(stderr, "host-sshandler: Failed to write minidump trigger: %s\n",
			strerror(errno));
	else
		fprintf(stdout, "host-sshandler: Minidump triggered via %s\n",
			minidump_path);

	fclose(fp);
}

static bool ath12k_snapshot_is_enabled(void)
{
	char path[MAX_PATH_LEN];
	char buf[8] = {0};
	DIR *dir;
	struct dirent *entry;
	FILE *fp;
	bool enabled = false;

	dir = opendir(ATH12K_DEBUGFS_ROOT);
	if (!dir)
		return false;

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s/%s/%s",
			 ATH12K_DEBUGFS_ROOT, entry->d_name,
			 ATH12K_ATH_DEBUG_DIR, ATH12K_SNAPSHOT_FILE);

		if (access(path, F_OK) != 0)
			continue;

		fp = fopen(path, "r");
		if (!fp)
			break;

		if (fgets(buf, sizeof(buf), fp) && buf[0] == '1')
			enabled = true;

		fclose(fp);
		break;
	}

	closedir(dir);
	return enabled;
}

static void create_host_snapshot(const char *event_name)
{
	char cmd[MAX_CMD_LEN];

	/* Proceed only if snapshot collection is enabled via debugfs */
	if (!ath12k_snapshot_is_enabled()) {
		fprintf(stdout, "host-sshandler: snapshot not enabled, skipping\n");
		return;
	}

	trigger_minidump();

	/* Wait 1500ms for minidump collection to complete */
	struct timespec ts = { .tv_sec = 1, .tv_nsec = 500000000 };

	nanosleep(&ts, NULL);

	/* 1. Create staging dir */
	snprintf(cmd, sizeof(cmd), "mkdir -p %s", HOST_DEBUG_DIR);
	system(cmd);

	/* 2. Collect logread into staging dir */
	snprintf(cmd, sizeof(cmd), "%s > %s/logread.txt 2>&1",
		 LOGREAD_CMD, HOST_DEBUG_DIR);
	if (system(cmd) != 0)
		fprintf(stderr, "host-sshandler: logread failed\n");

	/* 3. Move minidump into staging dir */
	snprintf(cmd, sizeof(cmd), "mv %s %s/ 2>/dev/null",
		 MINIDUMP_DIR, HOST_DEBUG_DIR);
	system(cmd);

	/* 4. Create tar at fixed well-known path */
	snprintf(cmd, sizeof(cmd), "tar -czf %s -C %s host_debug_logs 2>&1",
		 HOST_LOGS_FILE_PATH, TEMP_DIR);
	if (system(cmd) != 0) {
		fprintf(stderr, "host-sshandler: Failed to create diag tar\n");
		goto cleanup;
	}
	fprintf(stdout,
		"host-sshandler: Host debug snapshot tar created -> %s\n",
		HOST_LOGS_FILE_PATH);

	/* 5. Hand off to DA */
	da_interface_host_create_snapshot(event_name);

cleanup:
	snprintf(cmd, sizeof(cmd), "rm -rf %s", HOST_DEBUG_DIR);
	system(cmd);
}

void subsys_action_start(enum subsys_action_id act_id, uint16_t radio_id,
			 char * const *action_context,
			 enum ath12k_crit_err_type trigger)
{
	switch (act_id) {
	case SS_ACTION_ENABLE_DBG_LOGS:
		subsys_process_debug_masks(action_context, true);
		break;
	case SS_ACTION_INC_HAPD_VERBOSITY:
		enable_hapd_verbose_logs(radio_id);
		break;
	case SS_ACTION_SNAPSHOT:
		 create_host_snapshot(ath12k_crit_type_str(trigger));
		break;
	default:
		break;
}
}

void subsys_action_stop(enum subsys_action_id act_id, uint16_t radio_id, char * const * action_context)
{
	if (radio_id == USHRT_MAX) {
		fprintf(stdout, "host-sshandler : stopping action %d due to timeout\n", act_id);
	}

	switch (act_id) {
	case SS_ACTION_ENABLE_DBG_LOGS:
		subsys_process_debug_masks(action_context, false);
		break;
	case SS_ACTION_INC_HAPD_VERBOSITY:
		disable_hapd_verbose_logs(radio_id);
		break;
	default:
		break;
	}
}

static pthread_t host_window_thread;

static void *host_window_thread_fn(void *arg)
{
	struct subsys_ctx *ctx = (struct subsys_ctx *)arg;

	while (1) {
		subsys_update_action_windows(ctx);

		/* Sleep ~1s between checks */
		struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };

		nanosleep(&ts, NULL);
	}

	return NULL;
}

void host_start_window_thread(struct subsys_ctx *ctx)
{
	if (pthread_create(&host_window_thread, NULL,
			   host_window_thread_fn, ctx) != 0) {
		fprintf(stderr, "host-sshandler: failed to start window thread\n");
	}
}
