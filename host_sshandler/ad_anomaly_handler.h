// SPDX-License-Identifier: ISC
/* Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries. */

#ifndef AD_ANOMALY_HANDLER_H
#define AD_ANOMALY_HANDLER_H

#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <stdint.h>

#define HOST_MAX_ANOMALY_TRACKERS 8

#ifdef ANOMALY_NOTIFY_HDR_PRESENT
#include "anomaly_notify.h"
#else
// AD_CATEGORY_CONNECTIVITY anomaly types
typedef enum {
	ANOM_CONNECTIVITY_NONE = 0,
	ANOM_BEACON_STUCK = 1,
	ANOM_DATA_STALL = 2,
	ANOM_DISCONNECT = 3,
	ANOM_FAIL_CONNECT = 4
} anomaly_type_connectivity_t;

typedef enum {
	AD_CATEGORY_NONE = 0,
	AD_CATEGORY_CONNECTIVITY = 1,
	AD_CATEGORY_PERF = 2,
	AD_CATEGORY_NETWORK = 3
} ad_category_t;

typedef struct {
	uint8_t  ad_category;    /* ad_category_t value */
	uint8_t  anomaly_type;   /* anomaly type within that AD's own namespace, see below */
	uint8_t  reserved[2];    /* padding, keeps handler_data 4-byte aligned */
	uint32_t handler_data[20]; /* opaque, handler-specific scratch space (20 DWORDs = 80
				      bytes). Interpretation depends on ad_category/anomaly_type
				      — see the per-category trigger-condition overlays below. */
} anomaly_notify_header;

/*
 * AD_CATEGORY_CONNECTIVITY trigger-condition detail, overlaid onto the
 * leading DWORDs of anomaly_notify_header.handler_data. Lets the receiving
 * handler act on *why* the anomaly fired without re-deriving it from logs.
 */
typedef struct {
	uint32_t radio_id;           /* handler_data[0] */
	uint32_t band;                /* handler_data[1]: BAND_2G/5G/6G */
	uint32_t anomaly_hist_cnt;    /* handler_data[2]: anomalies in last 10 iterations */
	float    trigger_stat_value;  /* handler_data[3]: the stat that tripped the anomaly —
					 beacon_fail_rate / data_rtry_pct for BEACON_STUCK/
					 DATA_STALL, or disconnect count (as float) for
					 DISCONNECT; 0.0 if not applicable (FAIL_CONNECT) */
	/* remaining handler_data[4..19] reserved for future connectivity fields */
} anomaly_trigger_connectivity_t;
#endif

typedef struct {
	char   anomaly_name[64];
	int    occurrence_count;
	time_t first_detection_time;
	int    logs_collected;
} host_anomaly_tracker;

struct subsys_ctx;

bool ad_host_anomaly_handle_notification(struct subsys_ctx *ctx,
				    const char *msg_content,
				    size_t content_len);

#endif /* AD_ANOMALY_HANDLER_H */
