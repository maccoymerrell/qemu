/*
 * Stubs for the plugin block-device I/O hooks.
 *
 * block/block-backend.c reports every asynchronous block request to the
 * plugin devio hooks from its blk_aio_* issue and completion chokepoints.
 * The real implementations live in plugins/core.c, which only the emulator
 * targets link.  The standalone block utilities (qemu-io, qemu-nbd,
 * qemu-storage-daemon) and the block unit tests link libblock without the
 * plugin core, so they need these no-op definitions to resolve the calls.
 * Requests those tools issue have no guest execution to attribute to, so
 * reporting nothing is the correct behaviour rather than merely a
 * placeholder: returning 0 marks the request untracked, which suppresses
 * the matching completion notification.
 *
 * Author: Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/plugin.h"

uint64_t qemu_plugin_devio_start(int dir, uint64_t offset, uint64_t bytes,
                                 uint64_t dev_token)
{
    return 0;
}

void qemu_plugin_devio_stop(uint64_t request_id)
{
}
