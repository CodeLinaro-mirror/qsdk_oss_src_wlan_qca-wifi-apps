// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "net.h"

uint32_t udbg_enh_get_u32_le(const unsigned char *buf)
{
	return (uint32_t)buf[0] |
	       ((uint32_t)buf[1] << 8) |
	       ((uint32_t)buf[2] << 16) |
	       ((uint32_t)buf[3] << 24);
}

uint64_t udbg_enh_get_u64_le(const unsigned char *buf)
{
	return (uint64_t)udbg_enh_get_u32_le(buf) |
	       ((uint64_t)udbg_enh_get_u32_le(buf + 4) << 32);
}

void udbg_enh_put_u16_le(unsigned char *buf, uint16_t v)
{
	buf[0] = (unsigned char)(v & 0xFFu);
	buf[1] = (unsigned char)((v >> 8) & 0xFFu);
}

void udbg_enh_put_u32_le(unsigned char *buf, uint32_t v)
{
	buf[0] = (unsigned char)(v & 0xFFu);
	buf[1] = (unsigned char)((v >> 8) & 0xFFu);
	buf[2] = (unsigned char)((v >> 16) & 0xFFu);
	buf[3] = (unsigned char)((v >> 24) & 0xFFu);
}

void udbg_enh_put_u64_le(unsigned char *buf, uint64_t v)
{
	udbg_enh_put_u32_le(buf, (uint32_t)(v & 0xFFFFFFFFull));
	udbg_enh_put_u32_le(buf + 4, (uint32_t)(v >> 32));
}

char *udbg_enh_trim_in_place(char *s)
{
	char *start;
	size_t len;

	if (!s)
		return s;

	start = s;
	while (*start && isspace((unsigned char)*start))
		start++;
	if (start != s)
		memmove(s, start, strlen(start) + 1);

	len = strlen(s);
	while (len > 0 && isspace((unsigned char)s[len - 1]))
		s[--len] = '\0';
	return s;
}

char *udbg_enh_path_dup(const char *src, size_t max_len)
{
	char *dst;
	size_t n;

	if (!src || src[0] == '\0' || max_len == 0)
		return NULL;

	n = strnlen(src, max_len);
	if (n == 0 || n >= max_len)
		return NULL;

	dst = (char *)malloc(n + 1);
	if (!dst)
		return NULL;

	memcpy(dst, src, n + 1);
	return dst;
}

char *udbg_enh_path_ndup(const char *src, size_t len, size_t max_len)
{
	char *dst;

	if (!src || len == 0 || max_len == 0 || len >= max_len)
		return NULL;

	dst = (char *)malloc(len + 1);
	if (!dst)
		return NULL;

	memcpy(dst, src, len);
	dst[len] = '\0';
	return dst;
}

int udbg_enh_set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags == -1)
		return -1;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		return -1;
	return 0;
}

int set_socket_buffers(int fd, int size)
{
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0)
		return -1;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0)
		return -1;
	return 0;
}

uint32_t clamp_udp_batch_size(uint32_t requested)
{
	if (requested == 0)
		return UDBG_ENH_UDP_BATCH_SIZE_DEFAULT;
	if (requested > UDBG_ENH_UDP_BATCH_SIZE_MAX)
		return UDBG_ENH_UDP_BATCH_SIZE_MAX;
	return requested;
}

uint64_t monotonic_now_us(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		return 0;
	return ((uint64_t)ts.tv_sec * 1000000ull) +
	       (uint64_t)(ts.tv_nsec / 1000);
}

static void udbg_enh_format_in_addr(const struct in_addr *addr, char *out,
				    size_t out_len)
{
	if (!out || out_len == 0)
		return;
	if (!addr) {
		snprintf(out, out_len, "unknown");
		return;
	}
	if (!inet_ntop(AF_INET, addr, out, (socklen_t)out_len))
		snprintf(out, out_len, "invalid");
}

void udbg_enh_format_sockaddr(const struct sockaddr_in *addr, char *out,
			      size_t out_len)
{
	char ip[INET_ADDRSTRLEN];
	unsigned int port = 0;

	if (!out || out_len == 0)
		return;
	if (!addr) {
		snprintf(out, out_len, "unknown");
		return;
	}
	udbg_enh_format_in_addr(&addr->sin_addr, ip, sizeof(ip));
	port = (unsigned int)ntohs(addr->sin_port);
	snprintf(out, out_len, "%s:%u", ip, port);
}
