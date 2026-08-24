// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <strings.h>
#include <arpa/inet.h>

#include "net.h"
#include "config.h"
#include "utils.h"

static const char UDBG_ENH_CFG_PREFIX[] = "udbg_enh_";

/*
 * parse_bool: Handles parse_bool operation.
 * @s: Input parameter.
 * @fallback: Input parameter.
 * @output: Returns function result status/value.
 */
static int parse_bool(const char *s, int fallback)
{
	if (!s)
		return fallback;
	if (strcmp(s, "1") == 0 || strcasecmp(s, "true") == 0 ||
		strcasecmp(s, "yes") == 0 || strcasecmp(s, "on") == 0)
		return 1;
	if (strcmp(s, "0") == 0 || strcasecmp(s, "false") == 0 ||
		strcasecmp(s, "no") == 0 || strcasecmp(s, "off") == 0)
		return 0;
	return fallback;
}

/*
 * parse_u32_range: Handles parse_u32_range operation.
 * @s: Input parameter.
 * @fallback: Input parameter.
 * @minv: Input parameter.
 * @maxv: Input parameter.
 * @output: Returns function result status/value.
 */
static uint32_t parse_u32_range(const char *s, uint32_t fallback,
				uint32_t minv, uint32_t maxv)
{
	char *end;
	unsigned long v;

	if (!s || *s == '\0')
		return fallback;

	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0')
		return fallback;
	if (v < (unsigned long)minv)
		return minv;
	if (v > (unsigned long)maxv)
		return maxv;
	return (uint32_t)v;
}

/*
 * parse_u16_range: Handles parse_u16_range operation.
 * @s: Input parameter.
 * @fallback: Input parameter.
 * @minv: Input parameter.
 * @maxv: Input parameter.
 * @output: Returns function result status/value.
 */
static uint16_t parse_u16_range(const char *s, uint16_t fallback,
				uint16_t minv, uint16_t maxv)
{
	return (uint16_t)parse_u32_range(s, fallback, minv, maxv);
}

/*
 * config_key_matches: Handles config_key_matches operation.
 * @key: Input parameter.
 * @base: Input parameter.
 * @output: Returns function result status/value.
 */
static int config_key_matches(const char *key, const char *base)
{
	size_t base_len;
	size_t pref_len;

	base_len = strlen(base);

	pref_len = sizeof(UDBG_ENH_CFG_PREFIX) - 1;
	if (strncmp(key, UDBG_ENH_CFG_PREFIX, pref_len) == 0 &&
		strlen(key) == pref_len + base_len &&
		strcmp(key + pref_len, base) == 0)
		return 1;

	return 0;
}

/*
 * parse_ipv4_strict: Validate IPv4 address string is non-empty and parsable.
 * @s: Input IPv4 address string.
 * @output: Returns 1 when @s is a valid IPv4 literal, otherwise 0.
 */
static int parse_ipv4_strict(const char *s)
{
	struct in_addr addr;

	if (!s || *s == '\0')
		return 0;

	return inet_pton(AF_INET, s, &addr) == 1;
}

/*
 * udbg_enh_config_deinit: Handles udbg_enh_config_deinit operation.
 * @cfg: Input parameter.
 * @output: No return value.
 */
void udbg_enh_config_deinit(struct udbg_enh_config *cfg)
{
	if (!cfg)
		return;
}

/*
 * udbg_enh_load_config: Handles udbg_enh_load_config operation.
 * @path: Input parameter.
 * @cfg: Input parameter.
 * @output: Returns function result status/value.
 */
int udbg_enh_load_config(const char *path, struct udbg_enh_config *cfg)
{
	FILE *f = NULL;
	char line[PATH_MAX + 128];
	unsigned int line_num = 0;

	if (!cfg)
		return -1;

	memset(cfg, 0, sizeof(*cfg));
	snprintf(cfg->server_ip, sizeof(cfg->server_ip), "%s",
		 DEFAULT_SERVER_IP);
	cfg->server_port = DEFAULT_SERVER_PORT;
	cfg->server_max_subscriptions = DEFAULT_SERVER_MAX_SUBSCRIPTIONS;
	cfg->server_max_log_entries = DEFAULT_SERVER_MAX_LOG_ENTRIES;
	cfg->stop_timeout_ms = DEFAULT_STOP_TIMEOUT_MS;
	cfg->stop_poll_us = DEFAULT_STOP_POLL_US;
	cfg->liveness_check_interval_ms =
		DEFAULT_LIVENESS_CHECK_INTERVAL_MS;
	cfg->stale_timeout_ms = DEFAULT_STALE_TIMEOUT_MS;
	cfg->transport = DEFAULT_TRANSPORT;
	cfg->udp_batch_enable = DEFAULT_UDP_BATCH_ENABLE;
	cfg->udp_batch_size = DEFAULT_UDP_BATCH_SIZE;
	cfg->udp_batch_budget_us = DEFAULT_UDP_BATCH_BUDGET_US;

	f = fopen(path, "r");
	if (!f)
		goto fail;

	while (fgets(line, sizeof(line), f)) {
		char *eq;
		++line_num;
		udbg_enh_trim_in_place(line);
		if (line[0] == '#' || line[0] == '\0')
			continue;
		eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = '\0';
		udbg_enh_trim_in_place(line);
		udbg_enh_trim_in_place(eq + 1);
		if (config_key_matches(line, "server_port"))
			cfg->server_port = parse_u16_range(eq + 1,
						cfg->server_port,
						SERVER_PORT_MIN,
						SERVER_PORT_MAX);
		else if (config_key_matches(line, "server_max_subscriptions"))
			cfg->server_max_subscriptions = parse_u32_range(
				eq + 1,
				cfg->server_max_subscriptions,
				1u, MAX_SUBSCRIPTIONS_LIMIT);
		else if (config_key_matches(line, "server_max_log_entries"))
			cfg->server_max_log_entries =
				parse_u32_range(eq + 1,
						cfg->server_max_log_entries,
						1u,
						MAX_LOG_ENTRIES_LIMIT);
		else if (config_key_matches(line, "server_ip_address")) {
			if (!parse_ipv4_strict(eq + 1)) {
				fprintf(stderr,
					"[udbg_enh-config] invalid server_ip_address='%s' at line %u (expected IPv4 address)\n",
					eq + 1,
					line_num);
				goto fail;
			}
			snprintf(cfg->server_ip, sizeof(cfg->server_ip), "%s",
				 eq + 1);
		} else if (config_key_matches(line, "control_socket_path")) {
			fprintf(stderr,
				"[udbg_enh-config] key '%s' at line %u is not supported; use server option -s <ctrl-socket>\n",
				line,
				line_num);
			goto fail;
		} else if (config_key_matches(line, "stop_timeout_ms"))
			cfg->stop_timeout_ms = parse_u32_range(eq + 1,
								cfg->stop_timeout_ms,
								1u,
								STOP_TIMEOUT_MS_LIMIT);
		else if (config_key_matches(line, "stop_poll_us"))
			cfg->stop_poll_us = parse_u32_range(eq + 1,
							cfg->stop_poll_us,
							1u,
							STOP_POLL_US_LIMIT);
		else if (config_key_matches(line, "liveness_check_interval_ms"))
			cfg->liveness_check_interval_ms =
				parse_u32_range(eq + 1,
						cfg->liveness_check_interval_ms,
						1u,
						LIVENESS_CHECK_INTERVAL_MS_LIMIT);
		else if (config_key_matches(line, "stale_timeout_ms"))
			cfg->stale_timeout_ms =
				parse_u32_range(eq + 1,
						cfg->stale_timeout_ms,
						1u,
						STALE_TIMEOUT_MS_LIMIT);
		else if (config_key_matches(line, "use_transport")) {
			if (strcmp(eq + 1, "tcp") == 0)
				cfg->transport = UDBG_ENH_TRANSPORT_TCP;
			else if (strcmp(eq + 1, "udp") == 0)
				cfg->transport = UDBG_ENH_TRANSPORT_UDP;
			else {
				cfg->transport = UDBG_ENH_TRANSPORT_UNDEFINED;
				fprintf(stderr,
					"[udbg_enh-config] invalid use_transport='%s' (expected tcp or udp)\n",
					eq + 1);
				goto fail;
			}
		} else if (config_key_matches(line, "udp_batch_enable"))
			cfg->udp_batch_enable = parse_bool(eq + 1, cfg->udp_batch_enable);
		else if (config_key_matches(line, "udp_batch_size"))
			cfg->udp_batch_size =
				parse_u32_range(eq + 1,
						cfg->udp_batch_size,
						1u,
						UDP_BATCH_SIZE_LIMIT);
		else if (config_key_matches(line, "udp_batch_budget_us"))
			cfg->udp_batch_budget_us =
				parse_u32_range(eq + 1,
						cfg->udp_batch_budget_us,
						0u,
						UDP_BATCH_BUDGET_US_LIMIT);
		else if (config_key_matches(line, "pcapng_enable")) {
			fprintf(stderr,
				"[udbg_enh-config] key '%s' at line %u is not supported; use server option -f <pcapng-file>\n",
				line,
				line_num);
			goto fail;
		} else if (config_key_matches(line, "pcapng_path")) {
			fprintf(stderr,
				"[udbg_enh-config] key '%s' at line %u is not supported; use server option -f <pcapng-file>\n",
				line,
				line_num);
			goto fail;
		}
	}

	cfg->server_ip[sizeof(cfg->server_ip) - 1] = '\0';
	if (!parse_ipv4_strict(cfg->server_ip)) {
		fprintf(stderr,
			"[udbg_enh-config] invalid effective server_ip_address='%s' (expected IPv4 address)\n",
			cfg->server_ip);
		goto fail;
	}
	fclose(f);
	return 0;

fail:
	if (f)
		fclose(f);
	udbg_enh_config_deinit(cfg);
	return -1;
}
