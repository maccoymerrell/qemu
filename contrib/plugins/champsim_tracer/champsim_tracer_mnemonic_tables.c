/*
 * Mnemonic/register/ISA classification tables for champsim_tracer.
 *
 * This translation unit is compiled as C (not C++) because the generated
 * Capstone mnemonic tables rely on non-monotonic designated array
 * initialisers, a C99/GNU-C feature that g++ does not fully implement
 * (it emits "sorry, unimplemented: non-trivial designated initializers
 * not supported").  All other champsim_tracer TUs are C++ and consume
 * these tables via the `extern` declarations in
 * champsim_tracer_mnemonics.h.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <stdint.h>

#include <qemu-plugin.h>

#define CHAMPSIM_MNEMONIC_TABLES_IMPL 1
#include "champsim_tracer_mnemonics.h"
