// SPDX-License-Identifier: ISC
/* Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries. */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>

#include "da_interface.h"
#include "subsys_core.h"
#include "ad_anomaly_handler.h"

static host_anomaly_tracker *find_or_create_anomaly_tracker(struct subsys_ctx *ctx,
							   const char *name)
{
	int i;

	for (i = 0; i < ctx->anomaly_tracker_count; i++) {
		if (strcmp(ctx->anomaly_trackers[i].anomaly_name, name) == 0)
			return &ctx->anomaly_trackers[i];
	}

	if (ctx->anomaly_tracker_count >= HOST_MAX_ANOMALY_TRACKERS) {
		fprintf(stderr,
			"HOST_SSHANDLER [ad_anomaly]: tracker table full, "
			"cannot track %s\n", name);
		return NULL;
	}

	host_anomaly_tracker *tracker = &ctx->anomaly_trackers[ctx->anomaly_tracker_count++];
	strlcpy(tracker->anomaly_name, name, sizeof(tracker->anomaly_name));
	tracker->occurrence_count     = 0;
	tracker->first_detection_time = 0;
	tracker->logs_collected       = 0;
	return tracker;
}

static void log_to_host_master_anomaly_log(const char *anomaly_name,
					   int occurrence,
					   const char *details)
{
	FILE *fp = fopen(HOST_MASTER_ANOMALY_LOG, "a");
	if (!fp)
		return;

	time_t now = time(NULL);
	char ts[64];
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
	fprintf(fp, "[%s] %s | Occurrence: %d | %s\n",
		ts, anomaly_name, occurrence, details);
	fclose(fp);
}
static void execute_ad_host_snapshot(struct subsys_ctx *ctx,
				     enum ath12k_crit_err_type crit_type,
				     const anomaly_trigger_connectivity_t *trig)
{
	const char *event_name = ath12k_crit_type_str(crit_type);
	struct ath12k_crit_record rec = {0};
	char log_buf[256];
	char ts[64];
	int current_count = 0;

	pthread_mutex_lock(&ctx->action_lock);

	host_anomaly_tracker *tracker = find_or_create_anomaly_tracker(ctx, event_name);
	if (!tracker) {
		pthread_mutex_unlock(&ctx->action_lock);
		return;
	}

	tracker->occurrence_count++;

	if (tracker->logs_collected) {
		current_count = tracker->occurrence_count;
		fprintf(stdout,
			"HOST_SSHANDLER [ad_anomaly]: subsequent occurrence #%d "
			"of %s — logging to master only\n",
			tracker->occurrence_count, event_name);
		fflush(stdout);
		pthread_mutex_unlock(&ctx->action_lock);
		snprintf(log_buf, sizeof(log_buf),
			 "band=%u | anomaly_hist_cnt=%u | trigger_stat_value=%f | LOGGED_ONLY",
			 trig->band, trig->anomaly_hist_cnt,
			 (double)trig->trigger_stat_value);
		log_to_host_master_anomaly_log(event_name, current_count, log_buf);
		return;
	}

	tracker->logs_collected       = 1;
	tracker->first_detection_time = time(NULL);

	pthread_mutex_unlock(&ctx->action_lock);

	fprintf(stdout,
		"HOST_SSHANDLER [ad_anomaly]: first occurrence of %s "
		"— collecting snapshot\n", event_name);

	mkdir(HOST_DEBUG_DIR, 0755);

	/* anomaly_info.txt */
	FILE *fp = fopen(HOST_DEBUG_DIR "/anomaly_info.txt", "w");
	if (fp) {
		time_t now = time(NULL);
		strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
		fprintf(fp, "Anomaly Type: %s\n", event_name);
		fprintf(fp, "Source: AD app (via DA SUBSYSTEM_NOTIFICATION_EVENT_OCCURRED)\n");
		fprintf(fp, "Detection Time: %s\n", ts);
		fprintf(fp, "AD radio_id: %u\n", trig->radio_id);
		fprintf(fp, "band: %u\n", trig->band);
		fprintf(fp, "anomaly_hist_cnt: %u\n", trig->anomaly_hist_cnt);
		fprintf(fp, "trigger_stat_value: %f\n", (double)trig->trigger_stat_value);
		fprintf(fp, "Occurrence: First\n");
		fprintf(fp, "Subsequent occurrences are logged in host_anomaly_master.log only.\n");
		fclose(fp);
	}

	/* anomaly_master.log */
	snprintf(log_buf, sizeof(log_buf),
		 "band=%u | anomaly_hist_cnt=%u | trigger_stat_value=%f | SNAPSHOT_TRIGGERED",
		 trig->band, trig->anomaly_hist_cnt,
		 (double)trig->trigger_stat_value);
	log_to_host_master_anomaly_log(event_name, tracker->occurrence_count, log_buf);

	rec.trigger  = crit_type;
	rec.radio_id = (uint16_t)trig->radio_id;
	subsys_handle_crit_record(ctx, &rec);
}

bool ad_host_anomaly_handle_notification(struct subsys_ctx *ctx,
				    const char *msg_content,
				    size_t content_len)
{
	anomaly_notify_header hdr;
	anomaly_trigger_connectivity_t trig;

	if (content_len != sizeof(anomaly_notify_header)) {
		fprintf(stderr, "HOST_SSHANDLER [ad_anomaly]: Size mismatch or NULL\n");
		return false;
	}

	memcpy(&hdr, msg_content, sizeof(hdr));

	fprintf(stdout,
		"HOST_SSHANDLER [ad_anomaly]: received ad_category=%u "
		"anomaly_type=%u\n",
		hdr.ad_category, hdr.anomaly_type);

	if (hdr.ad_category != AD_CATEGORY_CONNECTIVITY) {
		fprintf(stderr,
			"HOST_SSHANDLER [ad_anomaly]: Invalid category=%u\n",
			hdr.ad_category);
		return true;
	}

	memcpy(&trig, hdr.handler_data, sizeof(trig));

	switch ((anomaly_type_connectivity_t)hdr.anomaly_type) {
	case ANOM_FAIL_CONNECT:
		execute_ad_host_snapshot(ctx, ATH12K_CRIT_AD_FAIL_CONNECT, &trig);
		break;

	case ANOM_DISCONNECT:
		execute_ad_host_snapshot(ctx, ATH12K_CRIT_AD_DISCONNECT, &trig);
		break;

	default:
		fprintf(stdout,
			"HOST_SSHANDLER [ad_anomaly]: anomaly_type=%u not "
			"handled\n", hdr.anomaly_type);
		break;
	}

	return true;
}
