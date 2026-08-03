/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include <errno.h>
#include <stdbool.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "internal.h"

#define UDBG_CLIENT_CORE_UUID_FILE_PATH "udbg_ext_client.uuid"
#define UDBG_CLIENT_CORE_UUID_TEXT_LEN 36
#define UDBG_CLIENT_CORE_UUID_FILE_BUF_SIZE 128

/*
 * udbg_client_core_get_random_bytes: Fills a buffer with random bytes from
 * /dev/urandom.
 * @buf: Destination byte buffer to populate with random bytes.
 * @len: Number of random bytes to read into buf.
 *
 * @output: Returns 0 on success, or -1 on read/argument errors.
 */
static int udbg_client_core_get_random_bytes(uint8_t *buf, size_t len)
{
	size_t off = 0;

	if (!buf) {
		errno = EINVAL;
		return -1;
	}

	{
		int fd = open("/dev/urandom", O_RDONLY);

		if (fd < 0)
			return -1;

		while (off < len) {
			ssize_t ret = read(fd, buf + off, len - off);

			if (ret < 0) {
				if (errno == EINTR)
					continue;
				close(fd);
				return -1;
			}

			if (ret == 0) {
				close(fd);
				errno = EIO;
				return -1;
			}

			off += (size_t) ret;
		}

		close(fd);
	}

	return 0;
}

/*
 * udbg_client_core_uuid_hex_value: Converts one hex digit to its numeric nibble.
 * @c: Hex digit character to convert.
 * @value: Output nibble (0..15).
 *
 * @output: Returns 0 on success, or -1 for invalid input.
 */
static int udbg_client_core_uuid_hex_value(char c, uint8_t *value)
{
	if (!value) {
		errno = EINVAL;
		return -1;
	}

	if (c >= '0' && c <= '9') {
		*value = (uint8_t) (c - '0');
		return 0;
	}

	if (c >= 'a' && c <= 'f') {
		*value = (uint8_t) (c - 'a' + 10);
		return 0;
	}

	if (c >= 'A' && c <= 'F') {
		*value = (uint8_t) (c - 'A' + 10);
		return 0;
	}

	errno = EINVAL;
	return -1;
}

/*
 * udbg_client_core_uuid_parse_text: Parses canonical UUID text into 16 bytes.
 * @str: UUID string in xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format.
 * @uuid: Output 16-byte UUID.
 *
 * @output: Returns 0 on success, or -1 for invalid format/input.
 */
static int udbg_client_core_uuid_parse_text(const char *str,
	uint8_t uuid[UDBG_CLIENT_CORE_UUID_SIZE])
{
	const int hyphen_pos[] = { 8, 13, 18, 23 };
	size_t idx = 0;
	size_t out = 0;
	size_t hyphen_idx = 0;

	if (!str || !uuid) {
		errno = EINVAL;
		return -1;
	}

	if (strlen(str) != UDBG_CLIENT_CORE_UUID_TEXT_LEN) {
		errno = EINVAL;
		return -1;
	}

	while (idx < UDBG_CLIENT_CORE_UUID_TEXT_LEN) {
		uint8_t hi;
		uint8_t lo;

		if (hyphen_idx < (sizeof(hyphen_pos) / sizeof(hyphen_pos[0])) &&
		    idx == (size_t) hyphen_pos[hyphen_idx]) {
			if (str[idx] != '-') {
				errno = EINVAL;
				return -1;
			}
			hyphen_idx++;
			idx++;
			continue;
		}

		if (idx + 1 >= UDBG_CLIENT_CORE_UUID_TEXT_LEN ||
		    out >= UDBG_CLIENT_CORE_UUID_SIZE) {
			errno = EINVAL;
			return -1;
		}

		if (udbg_client_core_uuid_hex_value(str[idx], &hi) < 0 ||
		    udbg_client_core_uuid_hex_value(str[idx + 1], &lo) < 0)
			return -1;

		uuid[out++] = (uint8_t) ((hi << 4) | lo);
		idx += 2;
	}

	if (out != UDBG_CLIENT_CORE_UUID_SIZE) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

/*
 * udbg_client_core_uuid_is_rfc4122: Validates UUID variant/version nibbles.
 * @uuid: UUID bytes to validate.
 *
 * @output: Returns non-zero if UUID has RFC4122 variant and known version.
 */
static int udbg_client_core_uuid_is_rfc4122(
	const uint8_t uuid[UDBG_CLIENT_CORE_UUID_SIZE])
{
	uint8_t version;

	if (!uuid)
		return 0;

	if ((uuid[8] & 0xc0) != 0x80)
		return 0;

	version = (uint8_t) ((uuid[6] >> 4) & 0x0f);
	if (version < 1 || version > 8)
		return 0;

	return 1;
}

/*
 * udbg_client_core_uuid_format_text: Formats a 16-byte UUID to canonical text.
 * @uuid: UUID bytes to format.
 * @out: Output buffer of at least 37 bytes.
 *
 * @output: Returns 0 on success, or -1 for invalid input/format failure.
 */
static int udbg_client_core_uuid_format_text(
	const uint8_t uuid[UDBG_CLIENT_CORE_UUID_SIZE],
	char out[UDBG_CLIENT_CORE_UUID_TEXT_LEN + 1])
{
	int ret;

	if (!uuid || !out) {
		errno = EINVAL;
		return -1;
	}

	ret = snprintf(out, UDBG_CLIENT_CORE_UUID_TEXT_LEN + 1,
		       "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
		       "%02x%02x-%02x%02x%02x%02x%02x%02x",
		       uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5],
		       uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11],
		       uuid[12], uuid[13], uuid[14], uuid[15]);
	if (ret != UDBG_CLIENT_CORE_UUID_TEXT_LEN) {
		errno = EIO;
		return -1;
	}

	return 0;
}

/*
 * udbg_client_core_uuid_write_all: Writes an entire buffer to fd.
 * @fd: File descriptor to write.
 * @buf: Source buffer.
 * @len: Number of bytes to write.
 *
 * @output: Returns 0 on success, or -1 on write error.
 */
static int udbg_client_core_uuid_write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *ptr = (const uint8_t *) buf;
	size_t off = 0;

	if (fd < 0 || (!ptr && len)) {
		errno = EINVAL;
		return -1;
	}

	while (off < len) {
		ssize_t ret = write(fd, ptr + off, len - off);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		if (ret == 0) {
			errno = EIO;
			return -1;
		}

		off += (size_t) ret;
	}

	return 0;
}

/*
 * udbg_client_core_uuid_load_file: Reads and validates a UUID from file.
 * @path: UUID file path.
 * @uuid: Output UUID bytes.
 *
 * @output: Returns 0 when a valid UUID is loaded, or -1 otherwise.
 */
static int udbg_client_core_uuid_load_file(const char *path,
	uint8_t uuid[UDBG_CLIENT_CORE_UUID_SIZE])
{
	char buf[UDBG_CLIENT_CORE_UUID_FILE_BUF_SIZE];
	char *start;
	char *end;
	size_t off = 0;
	int fd;

	if (!path || !uuid) {
		errno = EINVAL;
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	while (off < sizeof(buf) - 1) {
		ssize_t ret = read(fd, buf + off, (sizeof(buf) - 1) - off);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			int saved_errno = errno;
			close(fd);
			errno = saved_errno;
			return -1;
		}

		if (ret == 0)
			break;

		off += (size_t) ret;
	}

	if (close(fd) < 0)
		return -1;

	buf[off] = '\0';

	start = buf;
	while (*start && isspace((unsigned char) *start))
		start++;

	end = start + strlen(start);
	while (end > start && isspace((unsigned char) end[-1]))
		end--;
	*end = '\0';

	if (udbg_client_core_uuid_parse_text(start, uuid) < 0)
		return -1;

	if (!udbg_client_core_uuid_is_rfc4122(uuid)) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

/*
 * udbg_client_core_uuid_store_file: Persists UUID to file in canonical format.
 * @path: UUID file path.
 * @uuid: UUID bytes to store.
 */
void udbg_client_core_uuid_store_file(const char *path,
	const uint8_t uuid[UDBG_CLIENT_CORE_UUID_SIZE])
{
	char uuid_text[UDBG_CLIENT_CORE_UUID_TEXT_LEN + 1];
	char line[UDBG_CLIENT_CORE_UUID_TEXT_LEN + 2];
	int fd;

	if (!path || !uuid) {
		errno = EINVAL;
		return;
	}

	if (udbg_client_core_uuid_format_text(uuid, uuid_text) < 0)
		return;

	memcpy(line, uuid_text, UDBG_CLIENT_CORE_UUID_TEXT_LEN);
	line[UDBG_CLIENT_CORE_UUID_TEXT_LEN] = '\n';
	line[UDBG_CLIENT_CORE_UUID_TEXT_LEN + 1] = '\0';

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return;

	if (udbg_client_core_uuid_write_all(fd, line, UDBG_CLIENT_CORE_UUID_TEXT_LEN + 1) < 0) {
		int saved_errno = errno;

		close(fd);
		errno = saved_errno;
		return;
	}

	if (close(fd) < 0)
		return;

	return;
}

/*
 * udbg_client_core_uuid_generate_v4: Generates an RFC4122 version-4 UUID.
 * @uuid: Output array that receives 16 UUID bytes.
 *
 * @output: Returns 0 when UUID generation succeeds, or -1 on failure.
 */
static int udbg_client_core_uuid_generate_v4(
	uint8_t uuid[UDBG_CLIENT_CORE_UUID_SIZE])
{
	if (udbg_client_core_get_random_bytes(uuid,
		UDBG_CLIENT_CORE_UUID_SIZE) < 0)
		return -1;

	/* UUID version 4. */
	uuid[6] = (uint8_t) ((uuid[6] & 0x0f) | 0x40);
	/* RFC4122 variant. */
	uuid[8] = (uint8_t) ((uuid[8] & 0x3f) | 0x80);

	return 0;
}

/*
 * udbg_client_core_uuid_random: Loads client UUID from file or creates one.
 * @uuid: Output array that receives 16 UUID bytes.
 *
 * @output: Returns 0 when UUID is available, or -1 on generation failure.
 */
int udbg_client_core_uuid_random(uint8_t uuid[UDBG_CLIENT_CORE_UUID_SIZE])
{
	if (!uuid) {
		errno = EINVAL;
		return -1;
	}

	if (udbg_client_core_uuid_load_file(UDBG_CLIENT_CORE_UUID_FILE_PATH, uuid) == 0)
		return 0;

	if (udbg_client_core_uuid_generate_v4(uuid) < 0)
		return -1;

	/*
	 * Best-effort persistence: keep runtime UUID even when file creation/update
	 * fails.
	 */
	udbg_client_core_uuid_store_file(UDBG_CLIENT_CORE_UUID_FILE_PATH, uuid);
	return 0;
}

/*
 * udbg_client_core_timestamp_us: Reads current wall-clock time in microseconds.
 * @none: No input parameters.
 *
 * @output: Returns current timestamp in microseconds, or 0 if unavailable.
 */
uint64_t udbg_client_core_timestamp_us(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) == 0)
		return ((uint64_t) tv.tv_sec * 1000000ULL) +
		       (uint64_t) tv.tv_usec;

	return 0;
}

static bool udbg_client_core_buffer_exceeds_max_bytes(
	const struct udbg_client_core_buffer *buffer, size_t payload_len)
{
	if (!buffer || buffer->bytes > buffer->max_bytes)
		return true;

	return (payload_len > (buffer->max_bytes - buffer->bytes));
}

/*
 * udbg_client_core_buffer_init: Initializes ring buffer storage and limits.
 * @buffer: Buffer object to initialize before first enqueue operation.
 *
 * @output: Returns 0 on success, or -1 if setup/allocation fails.
 */
int udbg_client_core_buffer_init(struct udbg_client_core_buffer *buffer,
	size_t capacity, size_t max_bytes)
{
	if (!buffer || !capacity || !max_bytes ||
	    capacity > UDBG_CLIENT_CORE_BUFFER_MAX_CAPACITY ||
	    max_bytes > UDBG_CLIENT_CORE_BUFFER_MAX_BYTES_LIMIT) {
		errno = EINVAL;
		return -1;
	}

	if (capacity > SIZE_MAX / sizeof(*buffer->ring)) {
		errno = EOVERFLOW;
		return -1;
	}

	memset(buffer, 0, sizeof(*buffer));
	buffer->capacity = capacity;
	buffer->max_bytes = max_bytes;
	buffer->ring = calloc(buffer->capacity, sizeof(*buffer->ring));
	if (!buffer->ring) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

/*
 * udbg_client_core_buffer_deinit: Releases all queued records and buffer memory.
 * @buffer: Buffer object to tear down and reset.
 *
 * @output: No return value; clears all dynamic allocations and state fields.
 */
void udbg_client_core_buffer_deinit(struct udbg_client_core_buffer *buffer)
{
	if (!buffer)
		return;

	while (buffer->count)
		udbg_client_core_buffer_pop(buffer);

	free(buffer->ring);
	memset(buffer, 0, sizeof(*buffer));
}

/*
 * udbg_client_core_buffer_enqueue: Adds a log record to the ring buffer,
 * dropping oldest entries on pressure.
 * @buffer: Destination queue state.
 * @msg_type: Message type associated with the payload.
 * @payload: Pointer to payload bytes to copy into queue-owned memory.
 * @payload_len: Number of payload bytes to copy.
 * @timestamp: Timestamp stored with this queued record.
 *
 * @output: Returns 0 on enqueue success, or -1 on overflow/allocation errors.
 */
int udbg_client_core_buffer_enqueue(struct udbg_client_core_buffer *buffer,
	uint32_t msg_type, const void *payload, size_t payload_len,
	uint64_t timestamp)
{
	struct udbg_client_core_buffer_record *record;
	uint8_t *payload_copy = NULL;

	if (!buffer || !buffer->ring || !buffer->capacity) {
		errno = EINVAL;
		return -1;
	}
	if (payload_len && !payload) {
		errno = EINVAL;
		return -1;
	}
	if (payload_len > buffer->max_bytes) {
		errno = EMSGSIZE;
		return -1;
	}

	while (buffer->count &&
	       (buffer->count >= buffer->capacity ||
		udbg_client_core_buffer_exceeds_max_bytes(buffer, payload_len))) {
		udbg_client_core_buffer_pop(buffer);
	}

	if (buffer->count >= buffer->capacity ||
	    udbg_client_core_buffer_exceeds_max_bytes(buffer, payload_len)) {
		errno = ENOSPC;
		return -1;
	}

	if (payload_len) {
		payload_copy = malloc(payload_len);
		if (!payload_copy) {
			errno = ENOMEM;
			return -1;
		}
		memcpy(payload_copy, payload, payload_len);
	}

	record = &buffer->ring[buffer->tail];
	record->msg_type = msg_type;
	record->timestamp = timestamp;
	record->seqno = ++buffer->next_seq;
	record->payload_len = payload_len;
	record->payload = payload_copy;

	buffer->tail++;
	if (buffer->tail == buffer->capacity)
		buffer->tail = 0;
	buffer->count++;
	buffer->bytes += payload_len;

	return 0;
}

/*
 * udbg_client_core_buffer_peek: Returns the oldest queued record without
 * removing it.
 * @buffer: Buffer object to inspect.
 *
 * @output: Returns pointer to head record, or NULL when buffer is empty/invalid.
 */
const struct udbg_client_core_buffer_record *
udbg_client_core_buffer_peek(const struct udbg_client_core_buffer *buffer)
{
	if (!buffer || !buffer->ring || !buffer->count)
		return NULL;

	return &buffer->ring[buffer->head];
}

/*
 * udbg_client_core_buffer_pop: Removes and frees the oldest queued record.
 * @buffer: Buffer object whose head entry should be discarded.
 *
 * @output: No return value; queue shrinks by one when a record exists.
 */
void udbg_client_core_buffer_pop(struct udbg_client_core_buffer *buffer)
{
	struct udbg_client_core_buffer_record *record;
	uint8_t *payload;
	size_t payload_len;

	if (!buffer || !buffer->ring || !buffer->count)
		return;

	record = &buffer->ring[buffer->head];
	payload = record->payload;
	payload_len = record->payload_len;
	memset(record, 0, sizeof(*record));

	buffer->head++;
	if (buffer->head == buffer->capacity)
		buffer->head = 0;
	buffer->count--;
	buffer->bytes -= payload_len;
	free(payload);
}

/*
 * udbg_client_core_queue_log: Queues a log payload for deferred transmission.
 * @buffer: Buffer object that receives the queued payload.
 * @msg_type: Message type associated with this log payload.
 * @payload: Pointer to log payload bytes to queue.
 * @payload_len: Number of payload bytes to queue.
 *
 * @output: Returns 0 when queued, or -1 on failure.
 */
int udbg_client_core_queue_log(struct udbg_client_core_buffer *buffer,
	uint32_t msg_type, const void *payload, size_t payload_len)
{
	uint64_t ts;

	if (!buffer || !payload || !payload_len) {
		errno = EINVAL;
		return -1;
	}

	if (payload_len > (SIZE_MAX - UDBG_MSG_HEADER_SIZE -
				   UDBG_MSG_LOG_PREFIX_SIZE)) {
		errno = EOVERFLOW;
		return -1;
	}
	ts = udbg_client_core_timestamp_us();
	if (udbg_client_core_buffer_enqueue(buffer, msg_type, payload,
					    payload_len, ts) < 0)
		return -1;
	return 0;
}

/*
 * udbg_client_core_next_queued_wire_len: Computes wire size of next sendable
 * queued log entry.
 * @buffer: Buffer object to inspect.
 *
 * @output: Returns encoded length of next eligible queued log, or 0 if none.
 */
size_t udbg_client_core_next_queued_wire_len(
	const struct udbg_client_core_buffer *buffer)
{
	const struct udbg_client_core_buffer_record *record;

	record = udbg_client_core_buffer_peek(buffer);
	if (!record)
		return 0;

	return UDBG_MSG_HEADER_SIZE + UDBG_MSG_LOG_PREFIX_SIZE +
	       record->payload_len;
}

/*
 * udbg_client_core_build_next_queued_log: Encodes the next queued record into
 * a wire-format log frame.
 * @buffer: Buffer object that owns the queued record.
 * @subscribe_handle: Subscription handle used in the encoded log frame.
 * @out: Output buffer where encoded queued record is written.
 * @out_cap: Capacity of output buffer in bytes.
 * @out_len: Receives encoded length, or 0 when no entry is sendable.
 *
 * @output: Returns 0 when build succeeds (or no entry), or -1 on failure.
 */
int udbg_client_core_build_next_queued_log(
	const struct udbg_client_core_buffer *buffer, uint64_t subscribe_handle,
	uint8_t *out, size_t out_cap, size_t *out_len)
{
	const struct udbg_client_core_buffer_record *record;

	if (!buffer || !out || !out_len) {
		errno = EINVAL;
		return -1;
	}

	record = udbg_client_core_buffer_peek(buffer);
	if (!record) {
		*out_len = 0;
		return 0;
	}

	return udbg_client_core_proto_build_log(subscribe_handle,
		record->msg_type, record->timestamp, record->payload,
		record->payload_len, out, out_cap, out_len);
}
