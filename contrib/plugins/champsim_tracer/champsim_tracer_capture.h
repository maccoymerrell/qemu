/*
 * The comparison capture, and why it is not in the plugin.
 *
 * The apparatus that scores this classifier needs to see, per encoding, what
 * the classifier made of it.  There are three ways to get that and two of them
 * are wrong.
 *
 * A separate plugin would have to re-implement the classifier it is scoring,
 * and a scorer that re-implements its subject measures nothing.  Capture hooks
 * compiled into the shipping plugin are what the tree already did -- eight of
 * them, in the same file family where the lever rip-out had just removed
 * thirty-seven -- and they are apparatus living inside a product, which is the
 * thing that rip-out settled.
 *
 * So: one file, reachable through one call, and EMPTY unless the build was
 * configured for it.  The release object contains no capture code, no capture
 * symbol and none of the environment-variable names below, and that is a
 * property a reader can check with nm and strings rather than a promise.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_CAPTURE_H
#define CHAMPSIM_TRACER_CAPTURE_H

#include <cstddef>
#include <cstdint>

struct qemu_plugin_insn_info;
struct InsnFields;

#ifdef CST_CAPTURE

/*
 * Write this instruction's classification to whichever corpora the run asked
 * for.  Called once, at the end of classification, with everything the
 * apparatus keys on: the encoding bytes, the decoder's own words, and the
 * classification those produced.
 *
 * A corpus that was asked for and could not be written is a refusal, not a
 * silence: a short corpus reads downstream as an encoding the classifier had
 * nothing to say about, which is the silent false success this tree keeps
 * having to relearn.
 */
void cst_capture_insn(uint64_t pc, const void *bytes, size_t nbytes,
                      const struct qemu_plugin_insn_info *info,
                      const struct InsnFields *f);

#else

static inline void cst_capture_insn(uint64_t, const void *, size_t,
                                    const struct qemu_plugin_insn_info *,
                                    const struct InsnFields *)
{ }

#endif /* CST_CAPTURE */

#endif /* CHAMPSIM_TRACER_CAPTURE_H */
