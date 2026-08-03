// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef INTERNAL_H
#define INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "net.h"

struct udbg_enh_ring_entry {
	uint32_t msg_type;
	uint64_t handle;
	size_t packet_len;
	unsigned char *packet_data;
};

struct udbg_enh_ring_buffer {
	struct udbg_enh_ring_entry *entries;
	size_t capacity;
	size_t write_index;
	size_t count;
};

int udbg_enh_ring_init(struct udbg_enh_ring_buffer *rb, size_t capacity);
void udbg_enh_ring_deinit(struct udbg_enh_ring_buffer *rb);
int udbg_enh_ring_push(struct udbg_enh_ring_buffer *rb, uint32_t msg_type,
		       uint64_t handle, const unsigned char *packet,
		       size_t packet_len);

int subs_init(struct udbg_enh_subscription_table *t,
	      const struct udbg_enh_config *cfg);
void subs_deinit(struct udbg_enh_subscription_table *t);

struct udbg_enh_client_info *
subs_find_by_handle_any(struct udbg_enh_subscription_table *t, uint64_t handle);

struct udbg_enh_client_info *
subs_find_by_process_info(struct udbg_enh_subscription_table *t,
			  const struct udbg_enh_process_info *pinfo,
			  int include_inactive);

struct udbg_enh_client_info *
subs_find_next_stale_from_head(struct udbg_enh_subscription_table *t,
			       size_t *index);

void subs_advance_head(struct udbg_enh_subscription_table *t,
		       size_t written_index);

void subs_touch_client(struct udbg_enh_client_info *c, uint64_t now_us,
		       int active);

int subs_handle_exists(const struct udbg_enh_subscription_table *t,
		       uint64_t handle,
		       const struct udbg_enh_client_info *exclude);

uint64_t subs_generate_handle(const struct udbg_enh_subscription_table *t,
			      const struct udbg_enh_process_info *pinfo,
			      const struct udbg_enh_client_info *exclude);

int subs_udp_src_matches(const struct udbg_enh_client_info *ci,
			 const struct sockaddr_in *src);

#endif /* INTERNAL_H */
