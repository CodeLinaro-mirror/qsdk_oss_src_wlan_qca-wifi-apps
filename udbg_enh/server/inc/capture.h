// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef CAPTURE_H
#define CAPTURE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>

#include "net.h"

#define UDBG_ENH_PCAPNG_SNAPLEN 65535u
#define UDBG_ENH_PCAPNG_LINKTYPE_USER0 147u
#define UDBG_ENH_PCAPNG_SHB_TYPE 0x0A0D0D0Au
#define UDBG_ENH_PCAPNG_IDB_TYPE 0x00000001u
#define UDBG_ENH_PCAPNG_EPB_TYPE 0x00000006u
#define UDBG_ENH_PCAPNG_BYTE_ORDER 0x1A2B3C4Du
#define UDBG_ENH_PCAPNG_VER_MAJOR 1u
#define UDBG_ENH_PCAPNG_VER_MINOR 0u
#define UDBG_ENH_PCAPNG_INTERFACE_ID 0u

#define UDBG_ENH_LOG_PREFIX "[udbg_enh-server]"
#define UDBG_ENH_LOG(fmt, ...) \
	fprintf(stderr, UDBG_ENH_LOG_PREFIX " " fmt "\n", ##__VA_ARGS__)

enum udbg_enh_capture_rule_type {
	UDBG_ENH_CAPTURE_RULE_FILTER = 0,
	UDBG_ENH_CAPTURE_RULE_SCRAMBLE = 1,
};

struct udbg_enh_capture_rule {
	enum udbg_enh_capture_rule_type type;
	int negate;
	uint32_t match_offset;
	uint32_t match_length;
	unsigned char *match;
	uint32_t write_offset;
	uint32_t write_length;
	unsigned char write_value;
};

struct udbg_enh_capture_rules {
	int enabled;
	char path[256];
	size_t count;
	size_t capacity;
	size_t filter_count;
	size_t filter_not_count;
	size_t scramble_count;
	struct udbg_enh_capture_rule *rules;
};

struct udbg_enh_pcapng_context;

struct udbg_enh_pcapng_ops {
	int (*pcapng_open)(struct udbg_enh_pcapng_context *ctx, const char *path);
	int (*pcapng_write)(struct udbg_enh_pcapng_context *ctx, const void *data,
			    size_t len);
	int (*pcapng_close)(struct udbg_enh_pcapng_context *ctx);
	int (*pcapng_flush)(struct udbg_enh_pcapng_context *ctx);
};

struct udbg_enh_pcapng_context {
	char *pcapng_path;
	FILE *pcapng_fp;
	int open_status;
	int npackets;
	const struct udbg_enh_pcapng_ops *ops;
};

extern const struct udbg_enh_pcapng_ops udbg_enh_pcapng_default_ops;

void udbg_enh_capture_rules_deinit(struct udbg_enh_capture_rules *rules);

int udbg_enh_capture_rules_load(struct udbg_enh_capture_rules *rules,
				const char *path,
				char *err,
				size_t err_len);

int udbg_enh_capture_rules_pass(const struct udbg_enh_capture_rules *rules,
				const void *packet,
				size_t packet_len);

void udbg_enh_capture_rules_scramble(const struct udbg_enh_capture_rules *rules,
				     void *packet,
				     size_t packet_len);

void udbg_enh_pcapng_init(struct udbg_enh_pcapng_context *ctx);

int udbg_enh_pcapng_open(struct udbg_enh_pcapng_context *ctx, const char *path);

int udbg_enh_pcapng_write(struct udbg_enh_pcapng_context *ctx,
			  const void *data, size_t len);

int udbg_enh_pcapng_flush(struct udbg_enh_pcapng_context *ctx);

int udbg_enh_pcapng_close(struct udbg_enh_pcapng_context *ctx);

const char *udbg_enh_pcapng_path(const struct udbg_enh_pcapng_context *ctx);

#endif /* CAPTURE_H */
