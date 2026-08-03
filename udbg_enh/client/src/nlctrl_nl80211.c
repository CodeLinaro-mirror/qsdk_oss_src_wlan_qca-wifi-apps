/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "nlctrl_nl80211.h"

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif
#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK 0x3fff
#endif

#define UDBG_NLCTRL_MSG_TYPE 0x10u
#define UDBG_NLCTRL_ATTR_TYPE_FAMILY_NAME 0x0002u

static const uint8_t udbg_nlctrl_nl80211_name[] = {
	0x6e, 0x6c, 0x38, 0x30, 0x32, 0x31, 0x31, 0x00
};

void udbg_client_core_nlctrl_nl80211_buffer_init(
	struct udbg_client_core_nlctrl_nl80211_buffer *nlctrl_nl80211_buffer)
{
	if (!nlctrl_nl80211_buffer)
		return;

	nlctrl_nl80211_buffer->buf_len = 0;
	nlctrl_nl80211_buffer->buf = NULL;
}

void udbg_client_core_nlctrl_nl80211_buffer_deinit(
	struct udbg_client_core_nlctrl_nl80211_buffer *nlctrl_nl80211_buffer)
{
	if (!nlctrl_nl80211_buffer)
		return;

	free(nlctrl_nl80211_buffer->buf);
	nlctrl_nl80211_buffer->buf = NULL;
	nlctrl_nl80211_buffer->buf_len = 0;
}

static bool udbg_client_core_is_nlctrl_nl80211_attr(
	const struct nlattr *nla, size_t attrs_remaining)
{
	size_t nla_len;
	size_t value_len;
	const uint8_t *value;

	if (!nla || attrs_remaining < sizeof(*nla))
		return false;

	nla_len = nla->nla_len;
	if (nla_len < sizeof(*nla) || nla_len > attrs_remaining)
		return false;

	if ((nla->nla_type & NLA_TYPE_MASK) != UDBG_NLCTRL_ATTR_TYPE_FAMILY_NAME)
		return false;

	value_len = nla_len - sizeof(*nla);
	if (value_len != sizeof(udbg_nlctrl_nl80211_name))
		return false;

	value = (const uint8_t *) nla + sizeof(*nla);
	return memcmp(value, udbg_nlctrl_nl80211_name, sizeof(udbg_nlctrl_nl80211_name)) == 0;
}

bool is_nlctrl_nl80211(const void *payload, size_t payload_len)
{
	const struct nlmsghdr *nlh;
	const uint8_t *attrs;
	size_t attrs_len;
	size_t min_len;

	min_len = NLMSG_HDRLEN + sizeof(struct genlmsghdr);
	if (!payload || payload_len < min_len)
		return false;

	nlh = (const struct nlmsghdr *) payload;
	if (nlh->nlmsg_type != UDBG_NLCTRL_MSG_TYPE)
		return false;
	if (nlh->nlmsg_len < min_len || nlh->nlmsg_len > payload_len)
		return false;

	attrs = (const uint8_t *) payload + min_len;
	attrs_len = nlh->nlmsg_len - min_len;
	while (attrs_len >= sizeof(struct nlattr)) {
		const struct nlattr *nla = (const struct nlattr *) attrs;
		size_t aligned_len;

		if (udbg_client_core_is_nlctrl_nl80211_attr(nla, attrs_len))
			return true;

		if (nla->nla_len < sizeof(*nla) || nla->nla_len > attrs_len)
			return false;

		aligned_len = NLA_ALIGN((size_t) nla->nla_len);
		if (!aligned_len || aligned_len > attrs_len)
			return false;

		attrs += aligned_len;
		attrs_len -= aligned_len;
	}

	return false;
}

void udbg_client_core_add_to_nlctrl_nl80211_buffer(
	struct udbg_client_core_nlctrl_nl80211_buffer *nlctrl_nl80211_buffer,
	const void *payload, size_t payload_len)
{
	uint8_t *payload_copy;

	if (!nlctrl_nl80211_buffer || !payload || !payload_len) {
		errno = EINVAL;
		return;
	}

	payload_copy = malloc(payload_len);
	if (!payload_copy) {
		errno = ENOMEM;
		return;
	}

	memcpy(payload_copy, payload, payload_len);

	free(nlctrl_nl80211_buffer->buf);
	nlctrl_nl80211_buffer->buf = payload_copy;
	nlctrl_nl80211_buffer->buf_len = payload_len;
	return;
}
