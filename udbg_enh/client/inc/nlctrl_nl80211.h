/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef NLCTRL_NL80211_H
#define NLCTRL_NL80211_H

#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct udbg_client_core_nlctrl_nl80211_buffer {
	size_t buf_len;
	uint8_t *buf;
};

void udbg_client_core_nlctrl_nl80211_buffer_init(
	struct udbg_client_core_nlctrl_nl80211_buffer *nlctrl_nl80211_buffer);

void udbg_client_core_nlctrl_nl80211_buffer_deinit(
	struct udbg_client_core_nlctrl_nl80211_buffer *nlctrl_nl80211_buffer);

bool is_nlctrl_nl80211(const void *payload, size_t payload_len);

void udbg_client_core_add_to_nlctrl_nl80211_buffer(
	struct udbg_client_core_nlctrl_nl80211_buffer *nlctrl_nl80211_buffer,
	const void *payload, size_t payload_len);

#endif /* NLCTRL_NL80211_H */
