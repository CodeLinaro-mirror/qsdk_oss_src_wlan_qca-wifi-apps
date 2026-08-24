// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/types.h>

#include "capture.h"
#include "utils.h"

/*
 * write_section_header_block - Emit the pcapng Section Header Block (SHB).
 * @fp: Open output stream.
 *
 * Return: 0 on success, -1 on write failure.
 */
static int write_section_header_block(FILE *fp)
{
	unsigned char shb[28];

	memset(shb, 0, sizeof(shb));
	udbg_enh_put_u32_le(shb + 0, UDBG_ENH_PCAPNG_SHB_TYPE);
	udbg_enh_put_u32_le(shb + 4, (uint32_t)sizeof(shb));
	udbg_enh_put_u32_le(shb + 8, UDBG_ENH_PCAPNG_BYTE_ORDER);
	udbg_enh_put_u16_le(shb + 12, UDBG_ENH_PCAPNG_VER_MAJOR);
	udbg_enh_put_u16_le(shb + 14, UDBG_ENH_PCAPNG_VER_MINOR);
	udbg_enh_put_u64_le(shb + 16, UINT64_MAX); /* section length unknown */
	udbg_enh_put_u32_le(shb + 24, (uint32_t)sizeof(shb));

	return fwrite(shb, sizeof(shb), 1, fp) == 1 ? 0 : -1;
}

/*
 * write_interface_description_block - Emit the pcapng Interface Description Block.
 * @fp: Open output stream.
 *
 * Return: 0 on success, -1 on write failure.
 */
static int write_interface_description_block(FILE *fp)
{
	unsigned char idb[20];

	memset(idb, 0, sizeof(idb));
	udbg_enh_put_u32_le(idb + 0, UDBG_ENH_PCAPNG_IDB_TYPE);
	udbg_enh_put_u32_le(idb + 4, (uint32_t)sizeof(idb));
	udbg_enh_put_u16_le(idb + 8, (uint16_t)UDBG_ENH_PCAPNG_LINKTYPE_USER0);
	udbg_enh_put_u16_le(idb + 10, 0); /* reserved */
	udbg_enh_put_u32_le(idb + 12, UDBG_ENH_PCAPNG_SNAPLEN);
	udbg_enh_put_u32_le(idb + 16, (uint32_t)sizeof(idb));

	return fwrite(idb, sizeof(idb), 1, fp) == 1 ? 0 : -1;
}

static int udbg_enh_pcapng_default_open(struct udbg_enh_pcapng_context *ctx,
					const char *path);
static int udbg_enh_pcapng_default_write(struct udbg_enh_pcapng_context *ctx,
					 const void *data, size_t len);
static int udbg_enh_pcapng_default_close(struct udbg_enh_pcapng_context *ctx);
static int udbg_enh_pcapng_default_flush(struct udbg_enh_pcapng_context *ctx);

const struct udbg_enh_pcapng_ops udbg_enh_pcapng_default_ops = {
	.pcapng_open = udbg_enh_pcapng_default_open,
	.pcapng_write = udbg_enh_pcapng_default_write,
	.pcapng_close = udbg_enh_pcapng_default_close,
	.pcapng_flush = udbg_enh_pcapng_default_flush,
};

/*
 * udbg_enh_pcapng_init - Initialize a capture context with default operations.
 * @ctx: Context to initialize.
 */
void udbg_enh_pcapng_init(struct udbg_enh_pcapng_context *ctx)
{
	if (!ctx)
		return;
	memset(ctx, 0, sizeof(*ctx));
	ctx->ops = &udbg_enh_pcapng_default_ops;
}

/*
 * udbg_enh_pcapng_default_close - Close active file state in the default backend.
 * @ctx: Capture context.
 *
 * Frees path storage and resets open status even if file close fails.
 *
 * Return: 0 on success, -1 on invalid input or fclose() failure.
 */
static int udbg_enh_pcapng_default_close(struct udbg_enh_pcapng_context *ctx)
{
	int rc = 0;

	if (!ctx)
		return -1;

	if (ctx->pcapng_fp) {
		if (fclose(ctx->pcapng_fp) != 0)
			rc = -1;
		ctx->pcapng_fp = NULL;
	}
	free(ctx->pcapng_path);
	ctx->pcapng_path = NULL;
	ctx->open_status = 0;
	return rc;
}

/*
 * udbg_enh_pcapng_default_open - Open and bootstrap a new pcapng capture file.
 * @ctx: Capture context.
 * @path: Requested output path (suffix policy is enforced by config parsing).
 *
 * The function closes any previous handle, creates a new file, and writes
 * mandatory SHB/IDB headers.
 *
 * Return: 0 on success, -1 on validation, file, or header-write failure.
 */
static int udbg_enh_pcapng_default_open(struct udbg_enh_pcapng_context *ctx,
					const char *path)
{
	char *pcapng_path;
	size_t path_len;

	if (!ctx || !path)
		return -1;

	(void)udbg_enh_pcapng_default_close(ctx);
	path_len = strnlen(path, PATH_MAX);
	if (path_len == 0 || path_len >= PATH_MAX) {
		ctx->open_status = -1;
		return -1;
	}

	pcapng_path = udbg_enh_path_ndup(path, path_len, PATH_MAX);
	if (!pcapng_path) {
		ctx->open_status = -1;
		return -1;
	}

	ctx->pcapng_fp = fopen(pcapng_path, "wb");
	if (!ctx->pcapng_fp) {
		free(pcapng_path);
		ctx->open_status = -1;
		return -1;
	}

	if (write_section_header_block(ctx->pcapng_fp) < 0 ||
		write_interface_description_block(ctx->pcapng_fp) < 0) {
		fclose(ctx->pcapng_fp);
		ctx->pcapng_fp = NULL;
		remove(pcapng_path);
		free(pcapng_path);
		ctx->open_status = -1;
		return -1;
	}

	ctx->pcapng_path = pcapng_path;
	fflush(ctx->pcapng_fp);
	return 0;
}

/*
 * udbg_enh_pcapng_default_flush - Flush buffered capture data to storage.
 * @ctx: Capture context.
 *
 * Return: 0 on success, -1 on invalid context or fflush() failure.
 */
static int udbg_enh_pcapng_default_flush(struct udbg_enh_pcapng_context *ctx)
{
	if (!ctx || !ctx->pcapng_fp)
		return -1;
	return fflush(ctx->pcapng_fp) == 0 ? 0 : -1;
}

/*
 * udbg_enh_pcapng_default_write - Append one Enhanced Packet Block to the file.
 * @ctx: Capture context.
 * @data: Packet payload to store.
 * @len: Payload length in bytes.
 *
 * Timestamp is captured with gettimeofday() and encoded as microseconds.
 *
 * Return: 0 on success, -1 on validation, timestamp, or write failure.
 */
static int udbg_enh_pcapng_default_write(struct udbg_enh_pcapng_context *ctx,
					 const void *data, size_t len)
{
	struct timeval tv;
	unsigned char epb_hdr[28];
	uint64_t ts_us;
	uint32_t caplen;
	uint32_t pad_len;
	uint32_t total_len;
	unsigned char zero_pad[3] = { 0, 0, 0 };
	unsigned char block_len_bytes[4];

	if (!ctx || !ctx->pcapng_fp || !data || len == 0)
		return -1;
	if (len > UINT32_MAX - 32u - 3u)
		return -1;

	if (gettimeofday(&tv, NULL) != 0)
		return -1;

	ts_us = (uint64_t)tv.tv_sec * 1000000ull + (uint64_t)tv.tv_usec;
	caplen = (uint32_t)len;
	pad_len = (uint32_t)((4u - (caplen % 4u)) % 4u);
	total_len = 32u + caplen + pad_len;

	memset(epb_hdr, 0, sizeof(epb_hdr));
	udbg_enh_put_u32_le(epb_hdr + 0, UDBG_ENH_PCAPNG_EPB_TYPE);
	udbg_enh_put_u32_le(epb_hdr + 4, total_len);
	udbg_enh_put_u32_le(epb_hdr + 8, UDBG_ENH_PCAPNG_INTERFACE_ID);
	udbg_enh_put_u32_le(epb_hdr + 12, (uint32_t)(ts_us >> 32));
	udbg_enh_put_u32_le(epb_hdr + 16, (uint32_t)(ts_us & 0xffffffffu));
	udbg_enh_put_u32_le(epb_hdr + 20, caplen);
	udbg_enh_put_u32_le(epb_hdr + 24, caplen);

	if (fwrite(epb_hdr, sizeof(epb_hdr), 1, ctx->pcapng_fp) != 1)
		return -1;
	if (fwrite(data, len, 1, ctx->pcapng_fp) != 1)
		return -1;
	if (pad_len > 0 && fwrite(zero_pad, pad_len, 1, ctx->pcapng_fp) != 1)
		return -1;

	udbg_enh_put_u32_le(block_len_bytes, total_len);
	if (fwrite(block_len_bytes, sizeof(block_len_bytes), 1, ctx->pcapng_fp) != 1)
		return -1;

	(void)udbg_enh_pcapng_default_flush(ctx);
	return 0;
}

/*
 * udbg_enh_pcapng_open - Public API to open a capture file through ctx->ops.
 * @ctx: Capture context.
 * @path: Requested output path.
 *
 * Initializes the default ops table if absent, then delegates to backend open.
 *
 * Return: 0 on success, -1 on validation or backend failure.
 */
int udbg_enh_pcapng_open(struct udbg_enh_pcapng_context *ctx, const char *path)
{
	int rc;

	if (!ctx)
		return -1;
	if (!ctx->ops)
		ctx->ops = &udbg_enh_pcapng_default_ops;
	if (!ctx->ops->pcapng_open)
		return -1;
	rc = ctx->ops->pcapng_open(ctx, path);
	if (rc == 0) {
		ctx->open_status = 1;
		ctx->npackets = 0;
	} else {
		ctx->open_status = -1;
	}
	return rc;
}

/*
 * udbg_enh_pcapng_write - Public API to write one packet through ctx->ops.
 * @ctx: Capture context.
 * @data: Packet payload.
 * @len: Payload length in bytes.
 *
 * On success, increments @ctx->npackets.
 *
 * Return: 0 on success, -1 on validation or backend failure.
 */
int udbg_enh_pcapng_write(struct udbg_enh_pcapng_context *ctx,
			  const void *data, size_t len)
{
	int rc;

	if (!ctx)
		return -1;
	if (!ctx->ops)
		ctx->ops = &udbg_enh_pcapng_default_ops;
	if (!ctx->ops->pcapng_write)
		return -1;
	rc = ctx->ops->pcapng_write(ctx, data, len);
	if (rc == 0)
		ctx->npackets++;
	return rc;
}

/*
 * udbg_enh_pcapng_flush - Public API to flush buffered output through ctx->ops.
 * @ctx: Capture context.
 * Return: 0 on success, -1 on validation or backend failure.
 */
int udbg_enh_pcapng_flush(struct udbg_enh_pcapng_context *ctx)
{
	if (!ctx)
		return -1;
	if (!ctx->ops)
		ctx->ops = &udbg_enh_pcapng_default_ops;
	if (!ctx->ops->pcapng_flush)
		return -1;
	return ctx->ops->pcapng_flush(ctx);
}

/*
 * udbg_enh_pcapng_close - Public API to close capture resources via ctx->ops.
 * @ctx: Capture context.
 *
 * Return: 0 on success, -1 on validation or backend failure.
 */
int udbg_enh_pcapng_close(struct udbg_enh_pcapng_context *ctx)
{
	int rc;

	if (!ctx)
		return -1;
	if (!ctx->ops)
		ctx->ops = &udbg_enh_pcapng_default_ops;
	if (!ctx->ops->pcapng_close)
		return -1;
	rc = ctx->ops->pcapng_close(ctx);
	ctx->open_status = 0;
	return rc;
}

/*
 * udbg_enh_pcapng_path - Get current output path if capture context is valid.
 * @ctx: Capture context.
 *
 * Return: Non-empty output path string, or NULL if unavailable.
 */
const char *udbg_enh_pcapng_path(const struct udbg_enh_pcapng_context *ctx)
{
	if (!ctx || !ctx->pcapng_path || ctx->pcapng_path[0] == '\0')
		return NULL;
	return ctx->pcapng_path;
}

/*
 * set_error: Format and store an error message, then return failure.
 * @err: Destination buffer for the formatted error string.
 * @err_len: Size of the destination error buffer.
 * @fmt: printf-style format string for the error text.
 * @output: Always returns -1.
 * Note: Writes to @err only when buffer is valid and non-empty.
 */
static int set_error(char *err, size_t err_len, const char *fmt, ...)
{
	va_list ap;

	if (!fmt)
		return -1;
	if (err && err_len > 0) {
		va_start(ap, fmt);
		vsnprintf(err, err_len, fmt, ap);
		va_end(ap);
	}
	return -1;
}

/*
 * parse_u32_strict: Parse a strict decimal uint32 value within a range.
 * @s: Input numeric string.
 * @minv: Minimum accepted value.
 * @maxv: Maximum accepted value.
 * @out: Destination for parsed uint32 value.
 * @output: Returns 0 on success, -1 on parse/range failure.
 */
static int parse_u32_strict(const char *s, uint32_t minv, uint32_t maxv, uint32_t *out)
{
	char *end;
	unsigned long value;

	if (!s || !out || *s == '\0')
		return -1;

	errno = 0;
	value = strtoul(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0')
		return -1;
	if (value < (unsigned long)minv || value > (unsigned long)maxv)
		return -1;

	*out = (uint32_t)value;
	return 0;
}

/*
 * parse_u8_strict: Parse a strict 8-bit integer value.
 * @s: Input numeric string (base auto-detected).
 * @out: Destination for parsed 8-bit value.
 * @output: Returns 0 on success, -1 on parse/range failure.
 */
static int parse_u8_strict(const char *s, unsigned char *out)
{
	char *end;
	unsigned long value;

	if (!s || !out || *s == '\0')
		return -1;

	errno = 0;
	value = strtoul(s, &end, 0);
	if (errno != 0 || end == s || *end != '\0' || value > 255ul)
		return -1;

	*out = (unsigned char)value;
	return 0;
}

/*
 * parse_hex_nibble: Convert one hex character into a nibble value.
 * @c: Input character to decode.
 * @out: Destination for nibble value (0..15).
 * @output: Returns 0 for valid hex, -1 for invalid input.
 */
static int parse_hex_nibble(unsigned char c, unsigned char *out)
{
	if (!out)
		return -1;
	if (c >= '0' && c <= '9') {
		*out = (unsigned char)(c - '0');
		return 0;
	}
	if (c >= 'a' && c <= 'f') {
		*out = (unsigned char)(10 + (c - 'a'));
		return 0;
	}
	if (c >= 'A' && c <= 'F') {
		*out = (unsigned char)(10 + (c - 'A'));
		return 0;
	}
	return -1;
}

/*
 * parse_match_bytes: Parse rule match bytes from text or hex form.
 * @match_str: Input match string ("text", "0x..", or "hex:..").
 * @out: Destination byte buffer for parsed bytes.
 * @out_cap: Capacity of destination byte buffer.
 * @out_len: Destination for parsed byte count.
 * @output: Returns 0 on success, -1 on invalid format/size.
 */
static int parse_match_bytes(const char *match_str,
				 unsigned char *out,
				 size_t out_cap,
				 size_t *out_len)
{
	const char *p;
	int hex_mode = 0;
	int have_high = 0;
	unsigned char high = 0;
	size_t n = 0;

	if (!match_str || !out || !out_len)
		return -1;

	if (strncmp(match_str, "0x", 2) == 0) {
		p = match_str + 2;
		hex_mode = 1;
	} else if (strncasecmp(match_str, "hex:", 4) == 0) {
		p = match_str + 4;
		hex_mode = 1;
	} else {
		p = match_str;
	}

	if (!hex_mode) {
		n = strlen(match_str);
		if (n == 0 || n > out_cap)
			return -1;
		memcpy(out, match_str, n);
		*out_len = n;
		return 0;
	}

	while (*p) {
		unsigned char nibble;
		unsigned char ch = (unsigned char)*p;
		if (isspace(ch) || ch == ':' || ch == '-' || ch == '_') {
			p++;
			continue;
		}
		if (parse_hex_nibble(ch, &nibble) < 0)
			return -1;
		if (!have_high) {
			high = nibble;
			have_high = 1;
		} else {
			if (n >= out_cap)
				return -1;
			out[n++] = (unsigned char)((high << 4) | nibble);
			have_high = 0;
		}
		p++;
	}

	if (have_high || n == 0)
		return -1;

	*out_len = n;
	return 0;
}

/*
 * parse_csv_fields: Split a CSV-like line into in-place trimmed fields.
 * @input: Mutable input string containing comma-separated fields.
 * @fields: Output array receiving field pointers.
 * @fields_cap: Maximum number of field pointers to store.
 * @output: Returns number of parsed fields.
 */
static size_t parse_csv_fields(char *input, char **fields, size_t fields_cap)
{
	size_t count = 0;
	char *cursor;

	if (!input || !fields || fields_cap == 0)
		return 0;

	cursor = input;
	while (cursor && *cursor && count < fields_cap) {
		char *comma = strchr(cursor, ',');
		if (comma)
			*comma = '\0';
		udbg_enh_trim_in_place(cursor);
		fields[count++] = cursor;
		if (!comma)
			break;
		cursor = comma + 1;
	}

	return count;
}

/*
 * parse_filter_directive: Detect filter directive and optional negate suffix.
 * @directive: Rule directive text to inspect.
 * @negate: Output flag set to 1 for filter-not, else 0.
 * @output: Returns 1 when directive is filter/filter-not, else 0.
 */
static int parse_filter_directive(const char *directive, int *negate)
{
	const char *suffix;

	if (!directive || !negate)
		return 0;
	if (strcasecmp(directive, "filter") == 0) {
		*negate = 0;
		return 1;
	}
	if (strncasecmp(directive, "filter", 6) != 0)
		return 0;

	suffix = directive + 6;
	while (*suffix && (isspace((unsigned char)*suffix) || *suffix == '_' || *suffix == '-'))
		suffix++;
	if (strcasecmp(suffix, "not") == 0) {
		*negate = 1;
		return 1;
	}
	return 0;
}

/*
 * capture_rule_release: Release heap allocations owned by one rule.
 * @rule: Rule object whose resources should be released.
 * @output: No return value.
 */
static void capture_rule_release(struct udbg_enh_capture_rule *rule)
{
	if (!rule)
		return;
	free(rule->match);
	rule->match = NULL;
}

/*
 * ensure_rules_capacity: Grow the rules array to hold at least @need entries.
 * @rules: Rules container with dynamic rules array.
 * @need: Minimum required rule slots.
 * @err: Optional error output buffer.
 * @err_len: Size of @err.
 * @output: Returns 0 on success, -1 on allocation/overflow failure.
 */
static int ensure_rules_capacity(struct udbg_enh_capture_rules *rules,
				 size_t need,
				 char *err,
				 size_t err_len)
{
	size_t new_cap;
	struct udbg_enh_capture_rule *new_rules;

	if (!rules)
		return set_error(err, err_len, "rules object is null");
	if (need <= rules->capacity)
		return 0;
	if (need > SIZE_MAX / sizeof(*new_rules))
		return set_error(err, err_len, "rule count too large");

	new_cap = rules->capacity ? rules->capacity : 16;
	while (new_cap < need) {
		if (new_cap > SIZE_MAX / 2) {
			new_cap = need;
			break;
		}
		new_cap *= 2;
	}
	if (new_cap > SIZE_MAX / sizeof(*new_rules))
		return set_error(err, err_len, "rule count too large");

	new_rules = (struct udbg_enh_capture_rule *)realloc(
		rules->rules, new_cap * sizeof(*new_rules));
	if (!new_rules)
		return set_error(err, err_len, "failed to grow rules array");

	/*
	 * Ensure newly allocated slots are zero-initialized so deinit can safely
	 * walk and free by count even if parsing fails later.
	 */
	if (new_cap > rules->capacity) {
		size_t old_cap = rules->capacity;
		memset(new_rules + old_cap, 0,
		       (new_cap - old_cap) * sizeof(*new_rules));
	}
	rules->rules = new_rules;
	rules->capacity = new_cap;
	return 0;
}

/*
 * parse_match_clause: Parse and validate offset/length/match fields for a rule.
 * @rule: Rule object to populate with parsed match values.
 * @offset_str: Match offset string.
 * @length_str: Match length string.
 * @match_str: Match bytes string to parse.
 * @err: Optional error buffer for failure details.
 * @err_len: Size of the error buffer.
 * @output: Returns 0 on success, -1 on validation failure.
 */
static int parse_match_clause(struct udbg_enh_capture_rule *rule,
			      const char *offset_str,
			      const char *length_str,
			      const char *match_str,
			      char *err,
			      size_t err_len)
{
	size_t parsed_len = 0;
	size_t match_len;

	if (!rule || !offset_str || !length_str || !match_str)
		return set_error(err, err_len, "invalid rule arguments");

	capture_rule_release(rule);
	if (parse_u32_strict(offset_str, 0, UINT32_MAX, &rule->match_offset) < 0)
		return set_error(err, err_len, "invalid match offset '%s'", offset_str);
	if (parse_u32_strict(length_str, 1, UINT32_MAX,
				     &rule->match_length) < 0)
		return set_error(err, err_len, "invalid match length '%s'", length_str);
	if (rule->match_offset > UINT32_MAX - rule->match_length)
		return set_error(err, err_len, "match offset+length overflows");
	match_len = (size_t)rule->match_length;
	if (match_len == 0 || match_len != rule->match_length)
		return set_error(err, err_len, "invalid match length '%s'", length_str);

	rule->match = (unsigned char *)malloc(match_len);
	if (!rule->match)
		return set_error(err, err_len, "match allocation failed");

	if (parse_match_bytes(match_str,
			      rule->match,
			      match_len,
			      &parsed_len) < 0)
	{
		capture_rule_release(rule);
		return set_error(err, err_len, "invalid match bytes '%s'", match_str);
	}
	if (parsed_len != (size_t)rule->match_length)
	{
		capture_rule_release(rule);
		return set_error(err,
				 err_len,
				 "match length mismatch expected=%u parsed=%zu",
				 (unsigned int)rule->match_length,
				 parsed_len);
	}

	return 0;
}

/*
 * packet_range_matches: Check whether packet bytes match a rule's match region.
 * @packet: Packet byte buffer to inspect.
 * @packet_len: Size of the packet buffer.
 * @rule: Rule containing match offset, length, and bytes.
 * @output: Returns 1 when packet region matches, else 0.
 */
static int packet_range_matches(const unsigned char *packet,
				 size_t packet_len,
				 const struct udbg_enh_capture_rule *rule)
{
	size_t start;
	size_t needed;

	if (!packet || !rule)
		return 0;
	if (!rule->match)
		return 0;

	start = (size_t)rule->match_offset;
	needed = (size_t)rule->match_length;
	if (needed == 0 || start > packet_len || packet_len - start < needed)
		return 0;

	return memcmp(packet + start, rule->match, needed) == 0;
}

/*
 * packet_range_fits: Verify that an offset/length range is inside packet bounds.
 * @packet_len: Total packet size in bytes.
 * @offset: Start offset of the target range.
 * @length: Length of the target range.
 * @output: Returns 1 when range is valid, else 0.
 */
static int packet_range_fits(size_t packet_len, uint32_t offset, uint32_t length)
{
	size_t start = (size_t)offset;
	size_t needed = (size_t)length;

	if (needed == 0)
		return 0;
	if (start > packet_len || packet_len - start < needed)
		return 0;
	return 1;
}

/*
 * udbg_enh_capture_rules_deinit: Free and clear all capture rule state.
 * @rules: Rules object to deinitialize.
 * @output: No return value.
 */
void udbg_enh_capture_rules_deinit(struct udbg_enh_capture_rules *rules)
{
	size_t i;

	if (!rules)
		return;
	for (i = 0; i < rules->count; ++i)
		capture_rule_release(&rules->rules[i]);
	free(rules->rules);
	memset(rules, 0, sizeof(*rules));
}

/*
 * udbg_enh_capture_rules_load: Load and parse rules from a file path.
 * @rules: Rules container to fill.
 * @path: Filesystem path to the rules file.
 * @err: Optional error buffer for parse/load failures.
 * @err_len: Size of the error buffer.
 * @output: Returns 0 on success, -1 on error.
 * Note: Parsed counters and path fields are updated on success.
 */
int udbg_enh_capture_rules_load(struct udbg_enh_capture_rules *rules,
						const char *path,
						char *err,
						size_t err_len)
{
	FILE *fp = NULL;
	char *line = NULL;
	size_t line_cap = 0;
	ssize_t line_len;
	unsigned int lineno = 0;
	int rc = -1;

	if (!rules)
		return set_error(err, err_len, "rules object is null");

	udbg_enh_capture_rules_deinit(rules);

	if (!path || path[0] == '\0')
		return set_error(err, err_len, "rules path is empty");

	fp = fopen(path, "r");
	if (!fp)
		return set_error(err, err_len, "failed to open rules file '%s'", path);

	while ((line_len = getline(&line, &line_cap, fp)) >= 0) {
		char *directive;
		char *body;
		char *colon;
		char *fields[8];
		size_t nfields;
		int filter_negate = 0;
		struct udbg_enh_capture_rule rule = { 0 };
		char err_copy[192];

		lineno++;
		udbg_enh_trim_in_place(line);
		if (line[0] == '\0' || line[0] == '#')
			continue;

		colon = strchr(line, ':');
		if (!colon) {
			rc = set_error(err, err_len, "line %u: missing ':'", lineno);
			goto fail;
		}
		*colon = '\0';
		directive = udbg_enh_trim_in_place(line);
		body = udbg_enh_trim_in_place(colon + 1);
		if (body[0] == '\0') {
			rc = set_error(err, err_len, "line %u: missing rule body", lineno);
			goto fail;
		}

		nfields = parse_csv_fields(body, fields, sizeof(fields) / sizeof(fields[0]));

		if (parse_filter_directive(directive, &filter_negate)) {
			rule.type = UDBG_ENH_CAPTURE_RULE_FILTER;
			rule.negate = filter_negate;
			if (nfields != 3) {
				rc = set_error(err, err_len,
					       "line %u: filter/filter not expects 3 fields",
					       lineno);
				goto fail_with_rule;
			}
			if (parse_match_clause(&rule,
					       fields[0], fields[1], fields[2],
					       err, err_len) < 0) {
				snprintf(err_copy, sizeof(err_copy), "%s", err ? err : "invalid filter");
				rc = set_error(err, err_len, "line %u: %s", lineno, err_copy);
				goto fail_with_rule;
			}
			if (rule.negate)
				rules->filter_not_count++;
			else
				rules->filter_count++;
		} else if (strcasecmp(directive, "scramble") == 0) {
			rule.type = UDBG_ENH_CAPTURE_RULE_SCRAMBLE;
			if (nfields != 6) {
				rc = set_error(err, err_len, "line %u: scramble expects 6 fields",
					       lineno);
				goto fail_with_rule;
			}
			if (parse_match_clause(&rule,
					       fields[0], fields[1], fields[2],
					       err, err_len) < 0) {
				snprintf(err_copy, sizeof(err_copy), "%s", err ? err : "invalid scramble");
				rc = set_error(err, err_len, "line %u: %s", lineno, err_copy);
				goto fail_with_rule;
			}

			if (parse_u32_strict(fields[3], 0, UINT32_MAX, &rule.write_offset) < 0) {
				rc = set_error(err, err_len, "line %u: invalid write offset '%s'",
					       lineno, fields[3]);
				goto fail_with_rule;
			}
			if (parse_u32_strict(fields[4], 1, UINT32_MAX, &rule.write_length) < 0) {
				rc = set_error(err, err_len, "line %u: invalid write length '%s'",
					       lineno, fields[4]);
				goto fail_with_rule;
			}
			if (rule.write_offset > UINT32_MAX - rule.write_length) {
				rc = set_error(err, err_len, "line %u: write offset+length overflows",
					       lineno);
				goto fail_with_rule;
			}
			if (parse_u8_strict(fields[5], &rule.write_value) < 0) {
				rc = set_error(err, err_len, "line %u: invalid write value '%s'",
					       lineno, fields[5]);
				goto fail_with_rule;
			}
			rules->scramble_count++;
		} else {
			rc = set_error(err, err_len, "line %u: unsupported rule type '%s'",
				       lineno, directive);
			goto fail_with_rule;
		}

		if (ensure_rules_capacity(rules, rules->count + 1, err, err_len) < 0)
			goto fail_with_rule;
		rules->rules[rules->count++] = rule;
		rule.match = NULL;
		continue;

fail_with_rule:
		capture_rule_release(&rule);
		goto fail;
	}

	if (ferror(fp)) {
		rc = set_error(err, err_len, "failed to read rules file '%s'", path);
		goto fail;
	}

	rules->enabled = 1;
	snprintf(rules->path, sizeof(rules->path), "%s", path);
	rc = 0;

fail:
	if (fp)
		fclose(fp);
	free(line);
	if (rc < 0)
		udbg_enh_capture_rules_deinit(rules);
	return rc;
}

/*
 * udbg_enh_capture_rules_pass: Evaluate filter rules for a packet.
 * @rules: Loaded rules set used for filter decisions.
 * @packet: Packet buffer to test.
 * @packet_len: Packet size in bytes.
 * @output: Returns 1 when packet is allowed, else 0.
 */
int udbg_enh_capture_rules_pass(const struct udbg_enh_capture_rules *rules,
					const void *packet,
					size_t packet_len)
{
	const unsigned char *bytes;
	size_t i;
	int matched_positive_filter = 0;

	if (!rules || !rules->enabled)
		return 1;
	if (!packet || packet_len == 0)
		return 0;
	if (rules->filter_count == 0 && rules->filter_not_count == 0)
		return 1;

	bytes = (const unsigned char *)packet;
	for (i = 0; i < rules->count; ++i) {
		const struct udbg_enh_capture_rule *rule = &rules->rules[i];
		if (rule->type != UDBG_ENH_CAPTURE_RULE_FILTER)
			continue;
		if (!packet_range_matches(bytes, packet_len, rule))
			continue;
		if (rule->negate)
			return 0;
		matched_positive_filter = 1;
	}
	if (rules->filter_count > 0)
		return matched_positive_filter;
	return 1;
}

/*
 * udbg_enh_capture_rules_scramble: Apply matching scramble rules to a packet.
 * @rules: Loaded rules set containing scramble entries.
 * @packet: Mutable packet buffer to modify.
 * @packet_len: Packet size in bytes.
 * @output: No return value.
 */
void udbg_enh_capture_rules_scramble(const struct udbg_enh_capture_rules *rules,
					 void *packet,
					 size_t packet_len)
{
	unsigned char *bytes;
	size_t i;

	if (!rules || !rules->enabled || !packet || packet_len == 0)
		return;
	if (rules->scramble_count == 0)
		return;

	bytes = (unsigned char *)packet;
	for (i = 0; i < rules->count; ++i) {
		const struct udbg_enh_capture_rule *rule = &rules->rules[i];
		if (rule->type != UDBG_ENH_CAPTURE_RULE_SCRAMBLE)
			continue;
		if (!packet_range_matches(bytes, packet_len, rule))
			continue;
		if (!packet_range_fits(packet_len, rule->write_offset, rule->write_length))
			continue;
		memset(bytes + rule->write_offset,
		       (int)rule->write_value,
		       (size_t)rule->write_length);
	}
}
