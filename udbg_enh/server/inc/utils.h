// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

uint32_t udbg_enh_get_u32_le(const unsigned char *buf);
uint64_t udbg_enh_get_u64_le(const unsigned char *buf);

void udbg_enh_put_u16_le(unsigned char *buf, uint16_t v);
void udbg_enh_put_u32_le(unsigned char *buf, uint32_t v);
void udbg_enh_put_u64_le(unsigned char *buf, uint64_t v);

char *udbg_enh_trim_in_place(char *s);
char *udbg_enh_path_dup(const char *src, size_t max_len);
char *udbg_enh_path_ndup(const char *src, size_t len, size_t max_len);

int udbg_enh_set_nonblocking(int fd);
int set_socket_buffers(int fd, int size);
uint32_t clamp_udp_batch_size(uint32_t requested);
uint64_t monotonic_now_us(void);
void udbg_enh_format_sockaddr(const struct sockaddr_in *addr, char *out,
			      size_t out_len);

#endif /* UTILS_H */
