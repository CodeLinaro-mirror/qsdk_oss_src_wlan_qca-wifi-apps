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
#include "hapd_log_listener.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define ATH12K_DEBUGFS_ROOT "/sys/kernel/debug/ath12k"
#define ATH12K_BOOT_DBG_MASK_KEY "ath12k_debug_mask="
#define FW_PRINTENV_CMD "fw_printenv bootargs"
#define FW_SETENV_CMD_PREFIX "fw_setenv bootargs"
#define ATH12K_ATH_DEBUG_DIR "ath_debug"
#define ATH12K_DBGMASK_FILE "dbgmask"
#define DBGMASK_PREFIX "Current: "
#define MAX_PATH_LEN 512
#define MAX_MASK_BUF_LEN 512
#define FW_BOOTARGS_CMD_LEN 2048
#define FW_BOOTARGS_BUF_LEN 512
#define ATH12K_MINIDUMP_DIR_NAME "minidump"
#define ATH12K_MINIDUMP_COLLECT "collect"
#define TEMP_DIR "/tmp"
#define SYSLOG_NG_CMD  "cat /var/log/messages"
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
		fprintf(stderr, "HOST_SSHANDLER: Failed to open %s: %s\n",
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
	if (!fp) {
		fprintf(stderr, "HOST_SSHANDLER: Failed to open %s for read: %s\n",
			path, strerror(errno));
		return -errno;
	}

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
		fprintf(stderr, "HOST_SSHANDLER: Failed to open %s for write: %s\n",
			path, strerror(errno));
		return -errno;
	}

	fprintf(stderr, "HOST_SSHANDLER: Updating debug mask: '%s' -> '%s'\n",
		current_mask, new_mask);

	if (fprintf(fp, "%s\n", new_mask) < 0)
		ret = -EIO;
	else
		ret = 0;

	fclose(fp);
	return ret;
}

static const struct {
	const char *name;
	uint64_t bit;
} ath12k_dbg_mask_map[] = {
	{ "ahb",      1ULL << 0  },
	{ "wmi",      1ULL << 1  },
	{ "htc",      1ULL << 2  },
	{ "htt",      1ULL << 3  },
	{ "mac",      1ULL << 4  },
	{ "boot",     1ULL << 5  },
	{ "qmi",      1ULL << 6  },
	{ "data",     1ULL << 7  },
	{ "mgmt",     1ULL << 8  },
	{ "reg",      1ULL << 9  },
	{ "testmode", 1ULL << 10 },
	{ "hal",      1ULL << 11 },
	{ "pci",      1ULL << 12 },
	{ "dp_tx",    1ULL << 13 },
	{ "dp_rx",    1ULL << 14 },
	{ "wow",      1ULL << 15 },
	{ "fst",      1ULL << 16 },
	{ "peer",     1ULL << 17 },
	{ "ini",      1ULL << 18 },
	{ "qos",      1ULL << 19 },
	{ "mlme",     1ULL << 29 },
	{ "eapol",    1ULL << 30 },
	{ "dp_mon",   1ULL << 32 },
	{ "scan",     1ULL << 33 },
	{ "assoc",    1ULL << 34 },
	{ "roam",     1ULL << 35 },
	{ "dfs",      1ULL << 36 },
	{ "mlo",      1ULL << 40 },
};

static uint64_t subsys_action_compute_boot_dbgmask(char * const *action_context)
{
	uint64_t mask = 0;
	int i, j;

	for (i = 0; i < SSH_MAX_CTX_STRINGS && action_context[i]; i++) {
		for (j = 0; j < (int)ARRAY_SIZE(ath12k_dbg_mask_map); j++) {
			if (strcmp(action_context[i], ath12k_dbg_mask_map[j].name) == 0) {
				mask |= ath12k_dbg_mask_map[j].bit;
				break;
			}
		}
		if (j == (int)ARRAY_SIZE(ath12k_dbg_mask_map))
			fprintf(stderr, "HOST_SSHANDLER: unknown boot dbg mask name '%s', skipping\n",
				action_context[i]);
	}
	return mask;
}

static void subsys_action_set_boot_dbgmask(char * const *action_context)
{
	char buf[FW_BOOTARGS_BUF_LEN] = {0};
	char cleaned[FW_BOOTARGS_BUF_LEN] = {0};
	char cmd[FW_BOOTARGS_CMD_LEN];
	char *bootargs_val;
	char *mask_start;
	uint64_t dbg_mask;
	FILE *fp;

	fp = popen(FW_PRINTENV_CMD, "r");
	if (fp && fgets(buf, sizeof(buf), fp)) {
		pclose(fp);
	} else {
		if (fp)
			pclose(fp);
		fprintf(stderr, "HOST_SSHANDLER: failed to read bootargs via '%s'\n",
			FW_PRINTENV_CMD);
		return;
	}

	/* fw_printenv output: "bootargs=<value>\n" */
	bootargs_val = strchr(buf, '=');
	if (bootargs_val) {
		bootargs_val++;
	} else {
		fprintf(stderr, "HOST_SSHANDLER: unexpected fw_printenv output: %s\n", buf);
		return;
	}

	bootargs_val[strcspn(bootargs_val, "\n")] = '\0';

	mask_start = strstr(bootargs_val, ATH12K_BOOT_DBG_MASK_KEY);
	if (mask_start) {
		/* Mask present — issue reproduced after boot.
		 * Compute residual = existing_mask & ~our_mask.
		 * If zero: the mask was entirely ours — remove the token.
		 * If non-zero: another tool set some bits — preserve them. */
		char *before_end = mask_start;
		size_t prefix_len;
		char *after;
		uint64_t existing_mask, our_mask, residual;

		existing_mask = strtoull(mask_start + strlen(ATH12K_BOOT_DBG_MASK_KEY),
					 NULL, 0);
		our_mask = action_context ? subsys_action_compute_boot_dbgmask(action_context) : 0;
		residual = existing_mask & ~our_mask;

		if (before_end > bootargs_val && *(before_end - 1) == ' ')
			before_end--;

		prefix_len = before_end - bootargs_val;

		after = mask_start + strlen(ATH12K_BOOT_DBG_MASK_KEY);
		while (*after && *after != ' ')
			after++;

		if (residual) {
			/* Partial: rewrite token with residual bits only */
			char mask_tok[48];

			snprintf(mask_tok, sizeof(mask_tok), "%s0x%llx",
				 ATH12K_BOOT_DBG_MASK_KEY,
				 (unsigned long long)residual);
			snprintf(cleaned, sizeof(cleaned), "%.*s%s%s",
				 (int)prefix_len, bootargs_val, mask_tok, after);
			fprintf(stdout,
				"HOST_SSHANDLER: boot mask partially ours; preserving residual=0x%llx\n",
				(unsigned long long)residual);
		} else {
			/* Fully ours: remove the token entirely */
			snprintf(cleaned, sizeof(cleaned), "%.*s%s",
				 (int)prefix_len, bootargs_val, after);
			fprintf(stdout,
				"HOST_SSHANDLER: boot mask fully ours - removing (issue reproduced)\n");
		}

		snprintf(cmd, sizeof(cmd), "%s \"%s\"",
			 FW_SETENV_CMD_PREFIX, cleaned);
		fprintf(stdout, "HOST_SSHANDLER: fw_setenv cmd: %s\n", cmd);
		if (system(cmd) != 0)
			fprintf(stderr, "HOST_SSHANDLER: fw_setenv failed\n");
		return;
	}

	/* Mask absent — first trigger; inject for next boot */
	dbg_mask = action_context ? subsys_action_compute_boot_dbgmask(action_context) : 0;
	if (!dbg_mask) {
		fprintf(stderr,
			"HOST_SSHANDLER: no valid boot dbg mask names in action context\n");
		return;
	}

	snprintf(cmd, sizeof(cmd), "%s \"%s ath12k_debug_mask=0x%llx\"",
		 FW_SETENV_CMD_PREFIX, bootargs_val,
		 (unsigned long long)dbg_mask);
	fprintf(stdout,
		"HOST_SSHANDLER: setting boot dbg mask=0x%llx - reboot to capture. cmd: %s\n",
		(unsigned long long)dbg_mask, cmd);
	if (system(cmd) != 0)
		fprintf(stderr, "HOST_SSHANDLER: fw_setenv failed\n");
}


static void subsys_process_debug_masks(char * const * action_context, bool enable)
{
	char path[MAX_PATH_LEN];
	char current_mask[MAX_MASK_BUF_LEN];
	char new_mask[MAX_MASK_BUF_LEN];
	FILE *fp;
	int i, ret;

	if (!action_context)
		return;

	ret = ath12k_get_dbgmask_path(path, sizeof(path));
	if (ret < 0)
		return;

	ret = ath12k_read_current_mask(path, current_mask, sizeof(current_mask));
	if (ret < 0 && ret != -EIO)
		return;
	if (ret == -EIO)
		current_mask[0] = '\0';

	snprintf(new_mask, sizeof(new_mask), "%s", current_mask);
	for (i = 0; i < SSH_MAX_CTX_STRINGS && action_context[i] != NULL; i++) {
		char tmp[MAX_MASK_BUF_LEN];

		ath12k_update_mask_buffer(new_mask, action_context[i], enable, tmp, sizeof(tmp));
		snprintf(new_mask, sizeof(new_mask), "%s", tmp);
	}

	if (strcmp(current_mask, new_mask) == 0)
		return;

	fp = fopen(path, "w");
	if (!fp) {
		fprintf(stderr, "HOST_SSHANDLER: Failed to open %s for write: %s\n",
			path, strerror(errno));
		return;
	}

	fprintf(stderr, "HOST_SSHANDLER: Updating debug mask: '%s' -> '%s'\n",
		current_mask, new_mask);

	if (fprintf(fp, "%s\n", new_mask) < 0)
		fprintf(stderr, "HOST_SSHANDLER: Failed to write debug mask\n");

	fclose(fp);
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
		fprintf(stderr, "HOST_SSHANDLER: Failed to open %s: %s\n",
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

static bool trigger_minidump(void)
{
	char minidump_path[MAX_PATH_LEN];
	FILE *fp;
	int ret;

	ret = ath12k_get_minidump_path(minidump_path);
	if (ret < 0) {
		fprintf(stderr, "HOST_SSHANDLER: Cannot find minidump path\n");
		return false;
	}

	fp = fopen(minidump_path, "w");
	if (!fp) {
		fprintf(stderr, "HOST_SSHANDLER: Cannot open minidump trigger %s: %s\n",
			minidump_path, strerror(errno));
		return false;
	}

	if (fprintf(fp, "1\n") < 0)
		fprintf(stderr, "HOST_SSHANDLER: Failed to write minidump trigger: %s\n",
			strerror(errno));
	else
		fprintf(stdout, "HOST_SSHANDLER: Minidump triggered via %s\n",
			minidump_path);

	fclose(fp);
	return true;
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


static bool subsys_snap_collect_minidump(void)
{
	char cmd[MAX_CMD_LEN];
	struct timespec ts = { .tv_sec = 1, .tv_nsec = 500000000 };

	if(!trigger_minidump())
		return false;

	nanosleep(&ts, NULL);
	snprintf(cmd, sizeof(cmd), "mv %s %s/ 2>/dev/null", MINIDUMP_DIR, HOST_DEBUG_DIR);
	if (system(cmd) != 0) {
		fprintf(stderr, "HOST_SSHANDLER: minidump staging failed, MINIDUMP_DIR not found\n");
		return false;
	}

	return true;
}

static bool subsys_snap_collect_syslog(void)
{
	char cmd[MAX_CMD_LEN];

	snprintf(cmd, sizeof(cmd), "%s > %s/syslog.txt 2>&1", SYSLOG_NG_CMD, HOST_DEBUG_DIR);
	if (system(cmd) != 0) {
		fprintf(stderr, "HOST_SSHANDLER: syslog-ng log collection failed\n");
		return false;
	}

	return true;
}
struct snap_subcategory {
	const char *key;
	bool (*collect)(void);
};

static const struct snap_subcategory snap_subcategory_map[] = {
	{ SS_SNAP_KEY_MINIDUMP, subsys_snap_collect_minidump },
	{ SS_SNAP_KEY_SYSLOG,  subsys_snap_collect_syslog  },
};

static void create_host_snapshot(const char *event_name, char * const *snap_context)
{
	char cmd[MAX_CMD_LEN];
	int i, j, collected = 0;

	if (!ath12k_snapshot_is_enabled()) {
		fprintf(stdout, "HOST_SSHANDLER: snapshot not enabled, skipping\n");
		return;
	}

	if (!snap_context || !snap_context[0]) {
		fprintf(stderr, "HOST_SSHANDLER: SS_ACTION_SNAPSHOT: no subcategories specified, skipping snapshot\n");
		return;
	}

	snprintf(cmd, sizeof(cmd), "mkdir -p %s", HOST_DEBUG_DIR);
	system(cmd);

	for (i = 0; i < SSH_MAX_CTX_STRINGS && snap_context[i]; i++) {
		bool matched = false;

		for (j = 0; j < ARRAY_SIZE(snap_subcategory_map); j++) {
			if (strcmp(snap_context[i], snap_subcategory_map[j].key) == 0) {
				if (snap_subcategory_map[j].collect())
					collected++;
				matched = true;
				break;
			}
		}

		if (!matched)
			fprintf(stderr, "HOST_SSHANDLER: unknown snapshot subcategory / collection failure '%s', skipping\n",
				snap_context[i]);
	}

	if (!collected) {
		fprintf(stderr, "HOST_SSHANDLER: no subcategories collected, skipping tar\n");
		goto cleanup;
	}

	snprintf(cmd, sizeof(cmd), "tar -czf %s -C %s host_debug_logs 2>&1",
		 HOST_LOGS_FILE_PATH, TEMP_DIR);
	if (system(cmd) != 0) {
		fprintf(stderr, "HOST_SSHANDLER: Failed to create diag tar\n");
		goto cleanup;
	}
	fprintf(stdout, "HOST_SSHANDLER: Host debug snapshot tar created -> %s\n",
		HOST_LOGS_FILE_PATH);

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
		create_host_snapshot(ath12k_crit_type_str(trigger), action_context);
		break;
	case SS_ACTION_ENABLE_DBG_LOGS_ON_BOOT:
		subsys_action_set_boot_dbgmask(action_context);
		break;
	case SS_ACTION_HAPD_PEER_LOG:
		/* The listener thread is always running and responds to
		 * datagrams from hostapd directly.  Per-peer verbose logging
		 * is enabled by the listener on receipt of the trigger event;
		 * no action is needed here at window start. */
		break;
	default:
		break;
	}
}

void subsys_action_stop(enum subsys_action_id act_id, uint16_t radio_id, char * const * action_context, enum ath12k_crit_err_type trigger)
{
	if (radio_id == USHRT_MAX) {
		fprintf(stdout, "HOST_SSHANDLER : stopping action %d due to timeout\n", act_id);
	}

	switch (act_id) {
	case SS_ACTION_ENABLE_DBG_LOGS:
		subsys_process_debug_masks(action_context, false);
		break;
	case SS_ACTION_INC_HAPD_VERBOSITY:
		disable_hapd_verbose_logs(radio_id);
		break;
	case SS_ACTION_HAPD_PEER_LOG:
		hapd_log_listener_clear_all_peers();
		break;
	case SS_ACTION_SNAPSHOT:
		if (radio_id != USHRT_MAX)
			create_host_snapshot(ath12k_crit_type_str(trigger), action_context);
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
		fprintf(stderr, "HOST_SSHANDLER: failed to start window thread\n");
	}
}

