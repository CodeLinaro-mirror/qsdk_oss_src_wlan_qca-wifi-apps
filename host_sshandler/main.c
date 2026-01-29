/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "subsys_core.h"

volatile sig_atomic_t t_stop_flag = 0;

static void signal_handler(int signum)
{
	t_stop_flag = 1;
}

static int subsys_setup_signal_handlers(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) != 0) {
		fprintf(stderr, "host-sshandler : Failed to register SIGINT handler: %s\n", strerror(errno));
		return -1;
	}
	if (sigaction(SIGTERM, &sa, NULL) != 0) {
		fprintf(stderr, "host-sshandler : Failed to register SIGTERM handler: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct subsys_ctx ctx;
	pthread_t tid_crit = 0;
	int crit_idx;
	char devpath[32];

	memset(&ctx, 0, sizeof(ctx));
	if (subsys_setup_signal_handlers() != 0) {
		fprintf(stderr, "host-sshandler : Signal Handler setup failed.\n");
		return 1;
	}

	subsys_config_init_defaults(&ctx.cfg);

	if (!ctx.cfg.enable_crit_buffer) {
		fprintf(stderr, "host-sshandler : Critical Buffer is not enabled\n");
		return 0;
	}
	crit_idx = subsys_find_uio_dev("ath12k_log");
	if (crit_idx < 0) {
		fprintf(stderr, "host-sshandler : Cannot find UIO device ath12k_log\n");
		return 1;
	}
	snprintf(devpath, sizeof(devpath), "/dev/uio%d", crit_idx);
	ctx.crit_fd = open(devpath, O_RDWR | O_CLOEXEC);
	if (ctx.crit_fd < 0) {
		fprintf(stderr, "open(%s) failed: %s\n", devpath, strerror(errno));
		return 1;
	}
	long crit_sz = subsys_uio_read_map_size(crit_idx);
	printf("uio map size : %ld\n", crit_sz);
	if (crit_sz <= 0) {
		fprintf(stderr, "host-sshandler : crit map size invalid: %ld\n", crit_sz);
		close(ctx.crit_fd);
		return 1;
	}
	ctx.crit_map_size = (size_t)crit_sz;
	off_t offset = 1 * sysconf(_SC_PAGE_SIZE);
	ctx.crit_ring = mmap(NULL, ctx.crit_map_size,
			PROT_READ | PROT_WRITE, MAP_SHARED, ctx.crit_fd, offset);
	if (ctx.crit_ring == MAP_FAILED) {
		fprintf(stderr, "host-sshandler : mmap crit failed: %s\n", strerror(errno));
		close(ctx.crit_fd);
		return 1;
	}
	pthread_mutex_init(&ctx.action_lock, NULL);
	for (int i = 0; i < ATH12K_CRIT_MAX; i++) {
		ctx.trigger_state[i].trigger_id = (enum ath12k_crit_err_type)i;
		ctx.trigger_state[i].active = false;
		ctx.trigger_state[i].window_end_ns = 0;
		ctx.trigger_state[i].trigger_count = 0;
	}

	if (ctx.cfg.enable_crit_buffer) {
		if (pthread_create(&tid_crit, NULL, subsys_critical_buffer_monitor_thread, &ctx) != 0) {
			fprintf(stderr, "host-sshandler : Failed to create crit thread\n");
			t_stop_flag = 1;
		}
	}

	while (!t_stop_flag) {
		pause();
	}

	if (tid_crit) {
		pthread_join(tid_crit, NULL);
		printf("host-sshandler : Critical thread joined.\n");
	}

	pthread_mutex_destroy(&ctx.action_lock);
	munmap(ctx.crit_ring, ctx.crit_map_size);
	close(ctx.crit_fd);
	fprintf(stdout, "host-sshandler : Cleanup complete. Exiting.\n");

	return 0;
}
