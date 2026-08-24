// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "capture.h"

/*
 * udbg_enh_ring_init: Allocate and initialize packet ring storage.
 * @rb: Ring object to initialize.
 * @capacity: Number of entries to allocate.
 * @output: Returns 0 on success, -1 on invalid input/allocation failure.
 */
int udbg_enh_ring_init(struct udbg_enh_ring_buffer *rb, size_t capacity)
{
	if (!rb || capacity == 0)
		return -1;

	memset(rb, 0, sizeof(*rb));
	rb->entries =
		(struct udbg_enh_ring_entry *)calloc(capacity, sizeof(*rb->entries));
	if (!rb->entries)
		return -1;

	rb->capacity = capacity;
	return 0;
}

/*
 * udbg_enh_ring_deinit: Release packet ring storage and clear state.
 * @rb: Ring object to deinitialize.
 * @output: No return value.
 */
void udbg_enh_ring_deinit(struct udbg_enh_ring_buffer *rb)
{
	size_t i;

	if (!rb)
		return;

	if (rb->entries) {
		for (i = 0; i < rb->capacity; ++i)
			free(rb->entries[i].packet_data);
	}

	free(rb->entries);
	memset(rb, 0, sizeof(*rb));
}

/*
 * udbg_enh_ring_push: Store one accepted packet and metadata into ring.
 * @rb: Ring object receiving the entry.
 * @msg_type: Decoded message type of accepted packet.
 * @handle: Decoded handle of accepted packet.
 * @packet: Packet bytes to store.
 * @packet_len: Packet size in bytes.
 * @output: Returns 0 on success, -1 on validation/allocation failure.
 */
int udbg_enh_ring_push(struct udbg_enh_ring_buffer *rb, uint32_t msg_type,
		       uint64_t handle, const unsigned char *packet,
		       size_t packet_len)
{
	struct udbg_enh_ring_entry *entry;
	unsigned char *data = NULL;

	if (!rb || !rb->entries || rb->capacity == 0 || !packet)
		return -1;

	if (packet_len > 0) {
		data = (unsigned char *)malloc(packet_len);
		if (!data)
			return -1;
		memcpy(data, packet, packet_len);
	}

	entry = &rb->entries[rb->write_index];
	free(entry->packet_data);
	entry->packet_data = data;
	entry->packet_len = packet_len;
	entry->msg_type = msg_type;
	entry->handle = handle;
	rb->write_index = (rb->write_index + 1) % rb->capacity;
	if (rb->count < rb->capacity)
		rb->count++;

	return 0;
}

/*
 * client_reset_state: Reset client slot state.
 * @c: Client slot to reset.
 * @output: No return value.
 */
static void client_reset_state(struct udbg_enh_client_info *c)
{
	if (!c)
		return;
	free(c->nlctrl_nl80211_msg);
	c->nlctrl_nl80211_msg = NULL;
	c->fd = -1;
	c->handle = 0;
	memset(&c->addr, 0, sizeof(c->addr));
	c->active = 0;
	c->last_seen_us = 0;
	memset(&c->pid_info, 0, sizeof(c->pid_info));
}

/*
 * subs_used_count: Return number of initialized client slots.
 * @t: Subscription table.
 * @output: Number of slots to scan.
 */
static size_t subs_used_count(const struct udbg_enh_subscription_table *t)
{
	if (!t)
		return 0;
	if (t->table_full || t->nclients >= t->capacity)
		return t->capacity;
	return t->nclients;
}

/*
 * subs_init: Allocate and initialize subscription table storage.
 * @t: Subscription table object to initialize.
 * @cfg: Server configuration providing subscription capacity.
 * @output: Returns 0 on success, -1 on validation/allocation failure.
 */
int subs_init(struct udbg_enh_subscription_table *t,
	      const struct udbg_enh_config *cfg)
{
	size_t i;

	if (!t || !cfg || cfg->server_max_subscriptions == 0)
		return -1;

	memset(t, 0, sizeof(*t));
	t->capacity = (size_t)cfg->server_max_subscriptions;
	t->clients = (struct udbg_enh_client_info *)calloc(t->capacity,
							    sizeof(*t->clients));
	if (!t->clients)
		return -1;
	t->head = 0;
	t->table_full = false;
	t->nclients = 0;

	for (i = 0; i < t->capacity; ++i)
		client_reset_state(&t->clients[i]);
	return 0;
}

/*
 * subs_deinit: Release subscription table resources and client state.
 * @t: Subscription table object to deinitialize.
 * @output: No return value.
 */
void subs_deinit(struct udbg_enh_subscription_table *t)
{
	size_t i;
	size_t used;

	if (!t)
		return;
	used = subs_used_count(t);
	for (i = 0; i < used; ++i) {
		if (t->clients[i].fd >= 0)
			close(t->clients[i].fd);
		client_reset_state(&t->clients[i]);
	}
	free(t->clients);
	memset(t, 0, sizeof(*t));
}

/*
 * subs_find_by_handle_any: Look up client by handle regardless of active state.
 * @t: Subscription table to search.
 * @handle: Handle value to match.
 * @output: Returns matching client pointer, or NULL if none.
 */
struct udbg_enh_client_info *
subs_find_by_handle_any(struct udbg_enh_subscription_table *t, uint64_t handle)
{
	size_t i;
	size_t used;

	if (!t)
		return NULL;

	used = subs_used_count(t);
	for (i = 0; i < used; ++i) {
		if (t->clients[i].handle == handle)
			return &t->clients[i];
	}
	return NULL;
}

/*
 * subs_process_info_matches: Compare two process-identity tuples.
 * @a: First process identity.
 * @b: Second process identity.
 * @output: Returns 1 when PID/UUID/app_id all match, else 0.
 */
static int subs_process_info_matches(const struct udbg_enh_process_info *a,
				     const struct udbg_enh_process_info *b)
{
	if (!a || !b)
		return 0;
	if (a->pid != b->pid)
		return 0;
	if (memcmp(a->uuid, b->uuid, sizeof(a->uuid)) != 0)
		return 0;
	if (memcmp(a->app_id, b->app_id, sizeof(a->app_id)) != 0)
		return 0;
	return 1;
}

/*
 * subs_find_by_process_info: Find client slot by process identity tuple.
 * @t: Subscription table to search.
 * @pinfo: Process identity to match.
 * @include_inactive: Non-zero to search inactive slots as well.
 * @output: Returns matching client pointer, or NULL if not found.
 */
struct udbg_enh_client_info *
subs_find_by_process_info(struct udbg_enh_subscription_table *t,
			  const struct udbg_enh_process_info *pinfo,
			  int include_inactive)
{
	size_t i;
	size_t used;

	if (!t || !pinfo)
		return NULL;

	used = subs_used_count(t);
	for (i = 0; i < used; ++i) {
		struct udbg_enh_client_info *c = &t->clients[i];

		if (!include_inactive && !c->active)
			continue;
		if (subs_process_info_matches(&c->pid_info, pinfo))
			return c;
	}
	return NULL;
}

/*
 * subs_find_next_stale_from_head: Find first stale slot from circular head.
 * @t: Subscription table.
 * @index: Optional output stale slot index.
 * @output: Returns stale slot pointer, or NULL if none.
 */
struct udbg_enh_client_info *
subs_find_next_stale_from_head(struct udbg_enh_subscription_table *t,
			       size_t *index)
{
	size_t i;
	size_t idx;

	if (!t || !t->clients || t->capacity == 0 || !t->table_full)
		return NULL;

	for (i = 0; i < t->capacity; ++i) {
		idx = (t->head + i) % t->capacity;
		if (!t->clients[idx].active) {
			if (index)
				*index = idx;
			return &t->clients[idx];
		}
	}
	return NULL;
}

/*
 * subs_advance_head: Advance circular head after writing one slot.
 * @t: Subscription table.
 * @written_index: Index that was just written/replaced.
 * @output: No return value.
 */
void subs_advance_head(struct udbg_enh_subscription_table *t, size_t written_index)
{
	if (!t || t->capacity == 0)
		return;

	if (!t->table_full) {
		if (written_index >= t->nclients && t->nclients < t->capacity)
			t->nclients = written_index + 1;
		if (t->nclients >= t->capacity) {
			t->nclients = t->capacity;
			t->table_full = true;
		}
	}

	t->head = (written_index + 1) % t->capacity;
	if (!t->table_full && t->head == 0) {
		t->table_full = true;
		t->nclients = t->capacity;
	}
}

/*
 * subs_touch_client: Refresh client liveness timestamp and state.
 * @c: Client record to update.
 * @now_us: Monotonic timestamp in microseconds.
 * @active: Active-state value to set (0 or 1).
 * @output: No return value.
 */
void subs_touch_client(struct udbg_enh_client_info *c, uint64_t now_us, int active)
{
	if (!c)
		return;
	if (active == 0 || active == 1)
		c->active = active;
	c->last_seen_us = now_us;
}

/*
 * subs_handle_exists: Check whether handle already exists in table.
 * @t: Subscription table to inspect.
 * @handle: Candidate handle value.
 * @exclude: Optional slot to ignore during duplicate check.
 * @output: Returns 1 when handle is present/invalid, else 0.
 */
int subs_handle_exists(const struct udbg_enh_subscription_table *t,
		       uint64_t handle,
		       const struct udbg_enh_client_info *exclude)
{
	size_t i;
	size_t used;

	if (!t || handle == 0)
		return 1;
	used = subs_used_count(t);
	for (i = 0; i < used; ++i) {
		const struct udbg_enh_client_info *c = &t->clients[i];

		if (c == exclude)
			continue;
		if (c->handle == handle)
			return 1;
	}
	return 0;
}

/*
 * subs_generate_handle: Derive a subscription handle from process identity.
 * @t: Subscription table used for duplicate-handle checks.
 * @pinfo: Process identity source for handle bits.
 * @exclude: Optional slot excluded from duplicate detection.
 * @output: Returns derived handle value (may log collision warnings).
 */
uint64_t subs_generate_handle(const struct udbg_enh_subscription_table *t,
			      const struct udbg_enh_process_info *pinfo,
			      const struct udbg_enh_client_info *exclude)
{
	uint64_t handle = 0;

	if (pinfo) {
		handle |= ((uint64_t)(uint8_t)pinfo->uuid[0]) << 56;
		handle |= ((uint64_t)(uint8_t)pinfo->uuid[1]) << 48;
		handle |= ((uint64_t)(uint8_t)pinfo->uuid[2]) << 40;
		handle |= ((uint64_t)(uint8_t)pinfo->app_id[0]) << 32;
		handle |= ((uint64_t)(uint32_t)pinfo->pid);
	} else {
		UDBG_ENH_LOG("Handle cannot be created!");
	}

	if (subs_handle_exists(t, handle, exclude))
		UDBG_ENH_LOG("Duplicate handle 0x%llx has been generated",
			     (unsigned long long)handle);
	return handle;
}

/*
 * subs_udp_src_matches: Check whether UDP packet source matches subscriber.
 * @ci: Subscriber client record containing expected endpoint.
 * @src: Received source endpoint to validate.
 * @output: Returns 1 on endpoint match, else 0.
 */
int subs_udp_src_matches(const struct udbg_enh_client_info *ci,
			 const struct sockaddr_in *src)
{
	if (!ci || !src)
		return 0;
	if (ci->addr.sin_addr.s_addr != src->sin_addr.s_addr)
		return 0;
	if (ci->addr.sin_port != src->sin_port)
		return 0;
	return 1;
}
