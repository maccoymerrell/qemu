/*
 * wp-oldabi: a plugin built against an older plugin API, loaded next to
 * wp-assert by the wrong-path suite (WP_TESTS.md, net arm W1).  It declares
 * version 4 -- what a plugin built against a stock v10.0 qemu-plugin.h
 * declares, and inside the range the loader admits -- and does nothing
 * else.  Its presence must not stop another plugin from working.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdio.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = 4;

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    fprintf(stderr, "[wp-oldabi] installed, declaring plugin API version "
            "%d\n", qemu_plugin_version);
    return 0;
}
