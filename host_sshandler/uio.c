/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <limits.h>
#include "subsys_core.h"

#define UIO_NAME_SIZE (sizeof("/sys/class/uio/") - 1 + NAME_MAX + sizeof("/name"))

int subsys_find_uio_dev(const char *uio_buf_name)
{
	DIR *dir;
	struct dirent *dentry;
	char path[UIO_NAME_SIZE];
	char name[128];
	int idx = -1;

	dir = opendir("/sys/class/uio");
	if (!dir)
		return -1;

	while ((dentry = readdir(dir)) != NULL) {
		if (strncmp(dentry->d_name, "uio", 3) != 0)
			continue;

		int path_len = snprintf(path, sizeof(path),
				"/sys/class/uio/%s/name", dentry->d_name);
		if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
			continue;
		}

		FILE *uio_file = fopen(path, "r");
		if (!uio_file)
			continue;

		if (fgets(name, sizeof(name), uio_file)) {
			name[strcspn(name, "\n")] = '\0';
			if (strcmp(name, uio_buf_name) == 0) {
				idx = atoi(dentry->d_name + 3);
				fclose(uio_file);
				break;
			}
		}
		fclose(uio_file);
	}

	closedir(dir);
	return idx;
}

long subsys_uio_read_map_size(int uio_index)
{
	char path[64];
	unsigned long long map_size = 0;

	snprintf(path, sizeof(path), "/sys/class/uio/uio%d/maps/map1/size", uio_index);
	FILE *uio_file = fopen(path, "r");
	if (!uio_file)
		return -1;

	if (fscanf(uio_file, "%llx", &map_size) != 1) {
		fclose(uio_file);
		return -1;
	}
	fclose(uio_file);
	return (long)map_size;
}

void subsys_uio_drain_crit_ring(struct subsys_ctx *ctx)
{
	struct ath12k_crit_ring *ring = ctx->crit_ring;
	struct ath12k_crit_record *records = (struct ath12k_crit_record *)(ring + 1);
	uint32_t count = ring->count;
	uint32_t idx = ring->read_idx;
	struct ath12k_crit_record rec;

	while (idx != ring->write_idx) {
		rec = records[idx];
		subsys_handle_crit_record(ctx, &rec);
		idx = (idx + 1) % count;
	}
	ring->read_idx = idx;
	subsys_update_action_windows(ctx);
}
