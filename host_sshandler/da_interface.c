// SPDX-License-Identifier: ISC
/* Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.*/

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/sysinfo.h>
#include "da_interface.h"
#include "subsys_core.h"

void lib_init(TelemetryServiceAPPCallbacks *callbacks);
static TelemetryServiceAPPCallbacks *local_callbacks;

/* service_interrupt_from_telemetry_uio_driver :
 * Debug Agent specific callback that handles UIO interrupt notification.
 * Invoked when UIO interrupt is received from Kernel.
 */
void service_interrupt_from_telemetry_uio_driver(struct uio_interrupt_data *intr_data)
{
	/*
	 * The interrupt ring entry (map 0) carries:
	 *   mapId              = 0  (always set by debug_uio_notify — interrupt ring)
	 *   offset_from_base   = byte offset into map 1 (data ring) where data was
				  written
	 *   size_in_bytes_to_read = number of bytes written
	 *
	 * We must NOT read from maps[mapId] (map 0 = interrupt ring).
	 * Instead we call read_debug_uio_data() which reads from map 1 (data ring)
	 * at the given offset.
	 */
	uint8_t buf[PAYLOAD_SIZE];
	uint32_t read_size;
	int32_t ret;
	struct ath12k_crit_record *rec;

	if (!local_callbacks || !local_callbacks->read_debug_uio_data) {
		fprintf(stderr, "host-sshandler : read callback not available\n");
		return;
	}

	read_size = intr_data->size_in_bytes_to_read;
	if (read_size == 0) {
		fprintf(stderr, "host-sshandler : Buffer carries zero-length data\n");
		return;
	}
	if (read_size > (uint32_t)sizeof(buf)) {
		read_size = (uint32_t)sizeof(buf);
		fprintf(stdout,
			"host-sshandler: read size clamped to maximum buffer size\n");
	}

	memset(buf, 0, sizeof(buf));

	/*
	 * Read from map 1 (data ring) at the offset specified in the interrupt
	 * entry.  SUBSYSTEM_HANDLER_HOST_SUBSYSTEM_HANDLER identifies this handler
	 * to the debug agent so it looks up the correct UIO device/map.
	 */
	ret = local_callbacks->read_debug_uio_data(
			SUBSYSTEM_HANDLER_HOST_SUBSYSTEM_HANDLER,
			intr_data->offset_from_base,
			read_size,
			buf);

	if (ret != 0) {
		fprintf(stderr,
			"host-sshandler : read uio data failed: ret=%d", ret);
		fprintf(stderr, " handler=%d offset=%u size=%u)\n",
				SUBSYSTEM_HANDLER_HOST_SUBSYSTEM_HANDLER,
				intr_data->offset_from_base, read_size);
		return;
	}

	if (read_size >= sizeof(struct ath12k_crit_record)) {
		rec = (struct ath12k_crit_record *)buf;
		fprintf(stdout, "host-sshandler : ts_nsec=%llu trigger=%u radio_id=%u\n",
				(unsigned long long)rec->ts_nsec,
				rec->trigger,
				rec->radio_id);
	} else {
		fprintf(stderr, "host-sshandler : unexpected read_size=%u\n",
				read_size);
	}
}

/* ss_handler_uio_devices_maps_callback :
 *
 * Register HOST subsystem UIO routing with Debug Agent.
 *
 * This handler expects interrupts from UIO device 1, map 0:
 *   - uio_ids[0] = 1  -> "host" debug_uio device
 *   - map_ids[0] = 0  -> interrupt ring map
 *
 * After registration, Debug Agent forwards matching interrupt-ring entries
 * to service_interrupt_from_telemetry_uio_driver(), where payload data is
 * read from map 1 using read_debug_uio_data().
 */
void ss_handler_uio_devices_maps_callback(void)
{
	int32_t uio_ids[] = {HOST_UIO_ID};
	int32_t map_ids[] = {0};
	int32_t count = 1;

	if (!local_callbacks) {
		fprintf(stderr, "host-sshandler : Debug Agent callbacks are NULL\n");
		return;
	}

	if (local_callbacks->register_subsystem_handler_uio_devices_maps_callback) {
		local_callbacks->register_subsystem_handler_uio_devices_maps_callback(
				SUBSYSTEM_HANDLER_HOST_SUBSYSTEM_HANDLER,
				uio_ids, map_ids, count);
	} else {
		fprintf(stderr,
			"host-sshandler : %s registration failed\n",
			__func__);
	}
}

void lib_init(TelemetryServiceAPPCallbacks *callbacks)
{
	if (!callbacks) {
		fprintf(stderr, "host-sshandler : %s: Debug Agent callbacks are NULL\n",
			__func__);
		return;
	}

	local_callbacks = callbacks;
	ss_handler_uio_devices_maps_callback();
}
