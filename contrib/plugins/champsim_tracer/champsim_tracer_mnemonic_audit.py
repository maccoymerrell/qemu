#!/usr/bin/env python3
"""Audit and regenerate champsim_tracer mnemonic classification tables.

The script intentionally derives mnemonics from the in-tree Capstone C enum
names instead of Capstone's Python id-to-name API.  Some local Capstone Python
bindings can drift from the rebuilt C library, while the plugin compiles
against the C headers.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[3]
PLUGIN_DIR = Path(__file__).resolve().parent
IDENT_CORPUS_DIR = PLUGIN_DIR / "ident_corpus"
CAPSTONE_INCLUDE = ROOT / "subprojects" / "capstone" / "include" / "capstone"
GDB_XML_DIR = ROOT / "gdb-xml"


@dataclass(frozen=True)
class Entry:
    op: str
    branch: str = "BRANCH_NONE"
    flags: str = "MF_NONE"
    refine: str | None = None
    dep_refine: str | None = None    # shared refiner name, e.g.
                                     # "dep_mov_passthrough"; emitted
                                     # as `.dep_refine = <name>`.  NULL
                                     # → no HAS_REG block emitted (the
                                     # consumer falls back to implicit
                                     # all-to-all; the audit reports
                                     # these as unclassified).
    # Vector lane info.  Orthogonal to .dep_refine — these classify
    # whether the insn produces lane-mask FID records and whether the
    # lanes line up by index.  See InsnClassification in
    # champsim_tracer_mnemonics.h.
    lane_mask_kind: str = "LANE_MASK_KIND_NONE"
    lane_parallel: bool = False

    def without_refine(self) -> "Entry":
        """Strip preserved-across-runs annotations (.refine and
        .dep_refine), returning a bare op/branch/flags Entry.  Used
        by audit comparisons (rule-classified Entries never carry
        these annotations) and by generated_body's UNKNOWN-fallback,
        which re-attaches them explicitly afterwards."""
        return Entry(self.op, self.branch, self.flags)


@dataclass(frozen=True)
class IsaInfo:
    key: str
    prefix: str
    reg_prefix: str
    header: Path
    capstone_header: Path
    table: str
    array_size: str
    reg_table: str
    reg_array_size: str


ISAS = {
    "x86": IsaInfo(
        "x86",
        "X86_INS_",
        "X86_REG_",
        PLUGIN_DIR / "champsim_tracer_mnemonics_x86.h",
        CAPSTONE_INCLUDE / "x86.h",
        "x86_insn_class",
        "X86_INS_ENDING",
        "x86_reg_class",
        "X86_REG_ENDING",
    ),
    "aarch64": IsaInfo(
        "aarch64",
        "AARCH64_INS_",
        "AARCH64_REG_",
        PLUGIN_DIR / "champsim_tracer_mnemonics_aarch64.h",
        CAPSTONE_INCLUDE / "aarch64.h",
        "aarch64_insn_class",
        "AARCH64_INS_ENDING",
        "aarch64_reg_class",
        "AARCH64_REG_ENDING",
    ),
    "riscv": IsaInfo(
        "riscv",
        "RISCV_INS_",
        "RISCV_REG_",
        PLUGIN_DIR / "champsim_tracer_mnemonics_riscv.h",
        CAPSTONE_INCLUDE / "riscv.h",
        "riscv_insn_class",
        "RISCV_INS_ENDING",
        "riscv_reg_class",
        "RISCV_REG_ENDING",
    ),
    "mips": IsaInfo(
        "mips",
        "MIPS_INS_",
        "MIPS_REG_",
        PLUGIN_DIR / "champsim_tracer_mnemonics_mips.h",
        CAPSTONE_INCLUDE / "mips.h",
        "mips_insn_class",
        "MIPS_INS_ENDING",
        "mips_reg_class",
        "MIPS_REG_ENDING",
    ),
}


@dataclass(frozen=True)
class RegEntry:
    primary: str
    aliases: tuple[str, ...] = ()
    # True iff this is the ISA's integer-flags register (x86 EFLAGS,
    # aarch64 NZCV).  Drives REG_METAFLAGS canonicalisation in the
    # plugin; emitted as `.is_int_flags = true` in the reg-class
    # table when set.
    is_int_flags: bool = False

    @property
    def ignored(self) -> bool:
        return self.primary == "REG_NONE" and not self.aliases


@dataclass(frozen=True)
class QemuRegKey:
    feature: str
    name: str


@dataclass(frozen=True)
class GdbXmlFeature:
    feature_name: str
    regs: dict[str, int]
    names_by_local: tuple[str | None, ...]
    num_regs: int


ENTRY_RE = re.compile(
    # Match the dense designated array init format emitted by
    # format_entry: [CONST] = { .opcode = OP, .branch_type = BR,
    # .flags = F [, .refine=...] [, .dep_refine=...] }.  Accepts
    # the historical positional shape too (without member designators
    # on the struct fields) so the script can read pre-conversion
    # tables when preserving manual .refine overrides.
    r"\[\s*(?P<const>[A-Z][A-Z0-9_]+)\s*\]\s*=\s*\{\s*"
    r"(?:\.opcode\s*=\s*)?(?P<op>GEN_OP_[A-Z0-9_]+)\s*,\s*"
    r"(?:\.branch_type\s*=\s*)?(?P<branch>BRANCH_[A-Z0-9_]+)\s*,\s*"
    r"(?:\.flags\s*=\s*)?(?P<flags>(?:MF_[A-Z0-9_]+|0)(?:\s*\|\s*MF_[A-Z0-9_]+)*)\s*"
    r"(?:"
    r"(?:,\s*\.refine\s*=\s*(?P<refine>[A-Za-z_][A-Za-z0-9_]*))"
    r"|"
    r"(?:,\s*\.dep_refine\s*=\s*(?P<dep_refine>[A-Za-z_][A-Za-z0-9_]*))"
    r"|"
    r"(?:,\s*\.lane_mask_kind\s*=\s*(?P<lane_mask_kind>LANE_MASK_KIND_[A-Z_]+))"
    r"|"
    r"(?:,\s*\.lane_parallel\s*=\s*(?P<lane_parallel>true|false))"
    r")*"
    r"\s*\}",
    re.DOTALL,
)


# Shared refiner library, mirroring champsim_tracer_mnemonic_tables.c.
# Used to validate that .dep_refine names referenced from per-ISA
# tables actually exist; extend in lockstep with the C library.
DEP_REFINERS: set[str] = {
    "dep_passthrough",
    "dep_lea",
    "dep_x86_stack_push",
    "dep_x86_stack_pop",
    "dep_vec_struct_store",
}


# Per-ISA address-compute insns — Capstone marks their mem operand
# as CS_AC_READ even though no actual load fires at runtime, so the
# walker's HAS_ADDR auto-population yields a phantom load slot.
# dep_lea overrides that to keep the dst's rename slot dependent
# only on the address-component srcs.  Capstone's tables don't
# distinguish "true load" from "address-compute mem operand", so
# this list is curated manually per ISA from the architectural
# manuals.
# The ISAs whose address-compute mnemonic arrives with a phantom load slot
# for dep_lea to remove.  Only x86 does: LEA's operand is spelled as memory
# and Capstone tags it read.  The other three spell the same computation with
# an immediate and no MEM operand.
ISA_ADDRESS_COMPUTE_PHANTOM_LOAD: frozenset[str] = frozenset({"x86"})

ISA_ADDRESS_COMPUTE_INSNS: dict[str, set[str]] = {
    "x86":     {"X86_INS_LEA"},
    "aarch64": {"AARCH64_INS_ADR", "AARCH64_INS_ADRP"},
    "riscv":   {"RISCV_INS_AUIPC"},
    "mips":    set(),  # MIPS uses la/li pseudoinstructions assembled to
                       # ordinary lui+addi/ori; no dedicated address-compute
                       # mnemonic with a phantom-load problem.
}


# x86-specific override lists for the implicit-stack refiners.  These
# instructions push or pop to/from the stack via an implicit memop
# that Capstone doesn't enumerate as an explicit MEM operand — the
# refiner reconstructs the memop and points its address at the
# walker-discovered stack-pointer slot (RSP for most, RBP for LEAVE).
#
# Refiners are multi-memop-aware: PUSHA / POPA fan out 8 implicit
# memops, IRET pops IP+CS+EFLAGS, ENTER pushes a saved-frame chain.
# The refiner emits one implicit memop per non-stack-pointer reg in
# src_regs (push side) or dst_regs (pop side).
ISA_STACK_PUSH_INSNS: dict[str, set[str]] = {
    "x86":  {
        # Single-memop pushes
        "X86_INS_PUSH", "X86_INS_PUSHF", "X86_INS_PUSHFD", "X86_INS_PUSHFQ",
        "X86_INS_CALL", "X86_INS_LCALL",
        # Multi-memop fan-outs
        "X86_INS_PUSHAW", "X86_INS_PUSHAL", "X86_INS_ENTER",
    },
}
ISA_STACK_POP_INSNS: dict[str, set[str]] = {
    "x86":  {
        # Single-memop pops
        "X86_INS_POP", "X86_INS_POPF", "X86_INS_POPFD", "X86_INS_POPFQ",
        "X86_INS_RET", "X86_INS_RETF", "X86_INS_RETFQ",
        # LEAVE: stack pointer is RBP, not RSP — the intersection
        # heuristic in dep_x86_stack_pop catches that.
        "X86_INS_LEAVE",
        # Multi-memop fan-outs
        "X86_INS_POPAW", "X86_INS_POPAL",
        "X86_INS_IRET", "X86_INS_IRETD", "X86_INS_IRETQ",
    },
}


# Multi-register structured vector loads/stores whose dependency is
# precisely expressible by dep_vec_struct_* refiners (dep mask
# encodes which memops feed which dst register, rather than the
# pessimistic dep_all_to_all over-approximation).
#
# SEQUENTIAL: memops partition contiguously across the dst regs —
# slots [0, lanes_per_reg) → dst[0], [lanes_per_reg, 2*lanes_per_reg)
# → dst[1], etc.  AArch64 NEON LD1/ST1 with N>1 register list,
# AArch64 SVE single-Z LD1B/D/H/W/Q/SB/SH/SW (and fault-tolerant
# variants).  Single-reg cases also fit (they collapse to
# all-to-all on one dst, equivalent to the existing dep_all_to_all).
#
# INTERLEAVED: structure-deinterleave layout — slot k → dst (k %
# n_dst_regs).  AArch64 NEON LD2/LD3/LD4, SVE LD2B/3B/4B etc.,
# RISC-V V VLSEG2..VLSEG8 segment loads (and their strided /
# indexed / fault-first siblings).
#
# Replicate (LD1R / LD2R / LD3R / LD4R, SVE LD1R*) and broadcast
# variants are deliberately omitted — they fan ONE memop to MANY
# lanes (or replicate the same loaded value across dsts), a shape
# the dep_vec_struct refiners don't model.  They stay on
# dep_passthrough / dep_all_to_all, where a load → all-dst-lanes
# attribution is the best we have.
ISA_VEC_STRUCT_SEQUENTIAL_LOAD_INSNS: dict[str, set[str]] = {
    "aarch64": {
        # NEON multi-structure / SVE single-Z loads — sequential layout.
        "AARCH64_INS_LD1",
        "AARCH64_INS_LD1B", "AARCH64_INS_LD1D", "AARCH64_INS_LD1H",
        "AARCH64_INS_LD1Q", "AARCH64_INS_LD1W",
        "AARCH64_INS_LD1SB", "AARCH64_INS_LD1SH", "AARCH64_INS_LD1SW",
        "AARCH64_INS_LDFF1B", "AARCH64_INS_LDFF1D", "AARCH64_INS_LDFF1H",
        "AARCH64_INS_LDFF1W",
        "AARCH64_INS_LDFF1SB", "AARCH64_INS_LDFF1SH", "AARCH64_INS_LDFF1SW",
        "AARCH64_INS_LDNF1B", "AARCH64_INS_LDNF1D", "AARCH64_INS_LDNF1H",
        "AARCH64_INS_LDNF1W",
        "AARCH64_INS_LDNF1SB", "AARCH64_INS_LDNF1SH", "AARCH64_INS_LDNF1SW",
        # Multi-register GPR loads — same sequential partitioning
        # shape (each memop feeds one dst); the dep refiner doesn't
        # care that the dsts are scalar GPRs vs vector regs.  When
        # max_dep_loads doesn't divide evenly across n_dst_regs (e.g.
        # Capstone reports a single MEM operand) the refiner falls
        # back to dep_all_to_all internally — safe to bind broadly.
        "AARCH64_INS_LDP", "AARCH64_INS_LDPSW", "AARCH64_INS_LDNP",
        "AARCH64_INS_LDIAPP",
        "AARCH64_INS_LD64B",
    },
}
ISA_VEC_STRUCT_INTERLEAVED_LOAD_INSNS: dict[str, set[str]] = {
    "aarch64": {
        "AARCH64_INS_LD2",
        "AARCH64_INS_LD2B", "AARCH64_INS_LD2D", "AARCH64_INS_LD2H",
        "AARCH64_INS_LD2Q", "AARCH64_INS_LD2W",
        "AARCH64_INS_LD3",
        "AARCH64_INS_LD3B", "AARCH64_INS_LD3D", "AARCH64_INS_LD3H",
        "AARCH64_INS_LD3Q", "AARCH64_INS_LD3W",
        "AARCH64_INS_LD4",
        "AARCH64_INS_LD4B", "AARCH64_INS_LD4D", "AARCH64_INS_LD4H",
        "AARCH64_INS_LD4Q", "AARCH64_INS_LD4W",
    },
    "riscv": {
        # VLSEG2..VLSEG8 unit-stride, strided, indexed-ordered,
        # indexed-unordered, and their fault-first siblings — all
        # interleave by the segment factor.
        f"RISCV_INS_{prefix}{nf}E{ew}{ff}_V"
        for prefix in ("VLSEG", "VLSSEG")
        for nf in range(2, 9)
        for ew in (8, 16, 32, 64)
        for ff in ("", "FF")
        if not (prefix == "VLSSEG" and ff == "FF")
    } | {
        f"RISCV_INS_{prefix}{nf}EI{ew}_V"
        for prefix in ("VLOXSEG", "VLUXSEG")
        for nf in range(2, 9)
        for ew in (8, 16, 32, 64)
    },
}
ISA_VEC_STRUCT_SEQUENTIAL_STORE_INSNS: dict[str, set[str]] = {
    "aarch64": {
        # NEON / SVE multi-register stores — sequential layout.
        "AARCH64_INS_ST1",
        "AARCH64_INS_ST1B", "AARCH64_INS_ST1D", "AARCH64_INS_ST1H",
        "AARCH64_INS_ST1Q", "AARCH64_INS_ST1W",
        # Multi-register GPR stores (mirror of the LDP/STP family
        # above).  ST64BV / ST64BV0 are MTE-tagged variants with an
        # extra implicit-reg side effect and stay on dep_all_to_all
        # for now; ST64B fits the partitioning shape.
        "AARCH64_INS_STP", "AARCH64_INS_STNP", "AARCH64_INS_STILP",
        "AARCH64_INS_ST64B",
    },
}
ISA_VEC_STRUCT_INTERLEAVED_STORE_INSNS: dict[str, set[str]] = {
    "aarch64": {
        "AARCH64_INS_ST2",
        "AARCH64_INS_ST2B", "AARCH64_INS_ST2D", "AARCH64_INS_ST2H",
        "AARCH64_INS_ST2Q", "AARCH64_INS_ST2W",
        "AARCH64_INS_ST3",
        "AARCH64_INS_ST3B", "AARCH64_INS_ST3D", "AARCH64_INS_ST3H",
        "AARCH64_INS_ST3Q", "AARCH64_INS_ST3W",
        "AARCH64_INS_ST4",
        "AARCH64_INS_ST4B", "AARCH64_INS_ST4D", "AARCH64_INS_ST4H",
        "AARCH64_INS_ST4Q", "AARCH64_INS_ST4W",
    },
    "riscv": {
        f"RISCV_INS_{prefix}{nf}E{ew}_V"
        for prefix in ("VSSEG", "VSSSEG")
        for nf in range(2, 9)
        for ew in (8, 16, 32, 64)
    } | {
        f"RISCV_INS_{prefix}{nf}EI{ew}_V"
        for prefix in ("VSOXSEG", "VSUXSEG")
        for nf in range(2, 9)
        for ew in (8, 16, 32, 64)
    },
}

# ----------------------------------------------------------------------
# Capstone-source-driven dep-refiner classifier
#
# Capstone ships per-architecture tables describing every internal
# instruction variant — for x86 these are
# subprojects/capstone/arch/X86/X86Mapping{Insn,InsnOp}.inc.  Each
# internal variant (e.g. X86_ADD16rr) maps to a canonical Capstone
# insn id (X86_INS_ADD).  The internal-name suffix encodes the
# operand-type pattern (rr / rm / mr / ri / mi / i8 / r / m / ...)
# and the per-operand CS_AC_* flags say which operand is read,
# written, or read-modify-write.
#
# From those two signals we derive a runtime SHAPE per variant —
# exactly what shape the operand walker in champsim_tracer_decode.cc
# will produce when the dep_refine callback runs.  Aggregating shapes
# across all variants of one canonical insn id gives us the SHAPE SET
# that any refiner pointed at that id must correctly cover.  If every
# shape in the set fits a refiner's behavior group, we assign that
# refiner; otherwise the row stays unclassified (visible in the audit
# coverage report) until either the refiner library grows or a
# manual override lands.
# ----------------------------------------------------------------------

CAPSTONE_ARCH_DIR = ROOT / "subprojects" / "capstone" / "arch"


# Per-variant data from Capstone's source tables.
#
# `accesses` comes from X86MappingInsnOp.inc — per-operand CS_AC_*
# bits on the explicit operand list.
#
# `n_implicit_reads` / `n_implicit_writes` come from X86MappingInsn.inc
# — the regs_read[] / regs_write[] arrays that the operand walker
# folds into src_regs / dst_regs at template-build time when the ISA
# sets include_implicit_regs (x86 + aarch64 do).  Even one implicit
# read disqualifies dep_passthrough's "single value input" shape.
@dataclass(frozen=True)
class CapVariant:
    internal: str       # e.g. "X86_ADD16rr"
    canonical: str      # e.g. "X86_INS_ADD"
    accesses: tuple[str, ...]  # per-operand CS_AC_* expression strings
    # Per-operand CS_OP_* type strings, parallel to `accesses`.  Carried
    # so the classifier can distinguish identical access patterns where
    # the operand TYPES differ — most importantly mr-form stores
    # (CS_OP_MEM-WRITE + N CS_OP_REG-READ) from rrr arithmetic
    # (CS_OP_REG-WRITE + N CS_OP_REG-READ) which share (W, R, R).
    # Empty for ISAs whose Capstone tables don't expose per-operand
    # types (currently x86 — its operand types come from the variant
    # name suffix via parse_suffix_tokens instead).
    operand_types: tuple[str, ...]
    n_implicit_reads: int
    n_implicit_writes: int


# Capstone CS_OP_* type strings (or short tokens) that name memory
# operands.  The classifier consults these to tell an mr-form store
# apart from an rrr arithmetic insn whose access pattern is otherwise
# identical.  Both the "modern" Capstone style (full CS_OP_MEM
# string from the InsnOp tables) and the x86 suffix-token style
# ("m") are accepted so the audit can use the same comparison
# uniformly across ISAs.
_MEM_OPERAND_TYPES: frozenset[str] = frozenset({
    "CS_OP_MEM", "m",
})

# Operand-type tokens that name a register OR a memory ref — i.e.
# something a load/store under-tagging fallback could plausibly be
# narrowing.  Used to gate the all-degenerate fallback so a pure-IMM
# variant (a branch like MIPS `b target`, whose only operand is the
# CS_AC_READ immediate target) doesn't get reclassified to
# dep_passthrough.  Includes both "modern" CS_OP_* strings and the
# x86 suffix tokens used by parse_suffix_tokens.
_REG_OR_MEM_OPERAND_TYPES: frozenset[str] = frozenset({
    "CS_OP_REG", "CS_OP_MEM",
    "r", "m",
})


# Runtime shape we expect the operand walker to produce for one
# variant.  All fields are integers / booleans so shapes hash cleanly
# into sets.  Matches the InsnFields surface dep_refine reads.
@dataclass(frozen=True)
class WalkerShape:
    n_src_regs: int      # explicit reg src + addressing-mode srcs
    n_dst_regs: int      # explicit reg dst (RMW op[0] counts as both)
    max_dep_loads: int
    max_dep_stores: int
    has_imm: bool
    # Distinguishes "single-value-src in src_regs" cases — for rr
    # the value is src_regs[0]; for mr it's the LAST src_reg (the
    # walker added address-mode srcs first).  dep_passthrough's
    # mask choice depends on which.
    value_src_origin: str  # "first" | "last" | "load" | "imm" | "none"


# Operand-type token derived from a variant suffix character.  Each
# token says "what does this operand position look like to the
# walker": a register, a memory ref, an immediate, an implicit
# accumulator, or something we can't classify yet.
OPERAND_TOKENS = {"r", "m", "i"}


def _parse_x86_mapping_insn_implicit(text: str) -> dict[str, tuple[int, int]]:
    """Parse X86MappingInsn.inc → per-internal-name implicit reg counts.

    Each row has shape:
        { X86_<internal>, X86_INS_<canonical>, <groupbits>,
        #ifndef CAPSTONE_DIET
            { regs_read..., 0 }, { regs_write..., 0 },
            { groups..., 0 }, <branch>, <indirect_branch>
        #endif
        }
    We only need the lengths of regs_read and regs_write (0 sentinel
    excluded) to know whether an implicit register read/write is
    present.
    """
    insn_re = re.compile(
        r"\{\s*"
        r"(?P<internal>X86_[A-Za-z0-9_]+)\s*,\s*"
        r"X86_INS_[A-Za-z0-9_]+\s*,\s*"
        r"[^,]+,\s*"                                     # group bits — skip
        r"#ifndef\s+CAPSTONE_DIET\s*"
        r"\{\s*(?P<reads>[^}]*)\}\s*,\s*"
        r"\{\s*(?P<writes>[^}]*)\}\s*,\s*",
        re.DOTALL,
    )

    def count_nonzero(lst: str) -> int:
        toks = [t.strip() for t in lst.split(",") if t.strip()]
        if toks and toks[-1] == "0":
            toks.pop()
        return len(toks)

    out: dict[str, tuple[int, int]] = {}
    for m in insn_re.finditer(text):
        out[m.group("internal")] = (
            count_nonzero(m.group("reads")),
            count_nonzero(m.group("writes")),
        )
    return out


def _parse_modern_mapping_insn_implicit(
        text: str, internal_prefix: str, ins_prefix: str,
) -> dict[str, tuple[int, int]]:
    """Parse the "modern" Capstone <Arch>GenCSMappingInsn.inc layout
    used by aarch64 / riscv / mips.  Each entry looks like:

        {
          /* <comment> */
          <ArchPrefix>_<internal> /* N */, <ArchPrefix>_INS_<canon>,
          #ifndef CAPSTONE_DIET
            { regs_read..., 0 }, { regs_write..., 0 },
            { groups..., 0 }, <branch>, <indirect>,
            { .<arch> = { ... } }
          #endif
        },

    Same regs_read/regs_write semantics as the x86 layout — just with
    a trailing arch-specific struct we ignore.
    """
    insn_re = re.compile(
        r"\{\s*(?:/\*[^*]*\*/\s*)?"
        rf"(?P<internal>{re.escape(internal_prefix)}[A-Za-z0-9_]+)\s*"
        r"(?:/\*[^*]*\*/\s*)?,\s*"
        rf"{re.escape(ins_prefix)}[A-Za-z0-9_]+\s*,\s*"
        r"#ifndef\s+CAPSTONE_DIET\s*"
        r"\{\s*(?P<reads>[^}]*)\}\s*,\s*"
        r"\{\s*(?P<writes>[^}]*)\}\s*,\s*",
        re.DOTALL,
    )

    def count_nonzero(lst: str) -> int:
        toks = [t.strip() for t in lst.split(",") if t.strip()]
        if toks and toks[-1] == "0":
            toks.pop()
        return len(toks)

    out: dict[str, tuple[int, int]] = {}
    for m in insn_re.finditer(text):
        out[m.group("internal")] = (
            count_nonzero(m.group("reads")),
            count_nonzero(m.group("writes")),
        )
    return out


def _parse_modern_mapping_insn_op(
        text: str, internal_prefix: str, ins_prefix: str,
        implicit: dict[str, tuple[int, int]] | None = None,
) -> list[CapVariant]:
    """Parse the "modern" Capstone <Arch>GenCSMappingInsnOp.inc layout
    used by aarch64 / riscv / mips.  Each entry looks like:

        { /* <ArchPrefix>_<internal> (N) - <INS_PREFIX>_<canon> - <asm> */
        {
          { CS_OP_<TYPE>, CS_AC_<flags>, { ... } }, /* <name> */
          ...
          { 0 }
        }},

    Per-operand entries carry an operand-type field (CS_OP_*) AND an
    access-flag field (CS_AC_*).  We collect only the access flags
    here — the access-pattern classifier is type-agnostic, and the
    runtime walker reads the actual operand type from QEMU at trace
    time anyway.
    """
    entry_re = re.compile(
        r"/\*\s*"
        rf"(?P<internal>{re.escape(internal_prefix)}[A-Za-z0-9_]+)\s*"
        r"\(\d+\)\s*-\s*"
        rf"(?P<canonical>{re.escape(ins_prefix)}[A-Za-z0-9_]+)\s*"
        r"-[^*]*\*/",
    )
    # Operand entry inside the body: { CS_OP_X, CS_AC_X[ | CS_AC_X]*, { ... } }
    op_re = re.compile(
        r"\{\s*"
        r"(?P<type>CS_OP_[A-Z_]+)\s*,\s*"
        r"(?P<access>(?:CS_AC_[A-Z_]+(?:\s*\|\s*CS_AC_[A-Z_]+)*)|0)\s*,\s*"
        r"\{[^}]*\}\s*\}",
    )

    implicit = implicit or {}
    variants: list[CapVariant] = []
    headers = list(entry_re.finditer(text))
    for i, m in enumerate(headers):
        body_start = m.end()
        body_end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        body = text[body_start:body_end]
        ops_data = [(om.group("type"), om.group("access"))
                    for om in op_re.finditer(body)]
        # CS_OP entries with "0" as the access slot are Capstone's
        # placeholder for "ignore this operand"; the walker will ignore
        # them too.  Normalise to CS_AC_IGNORE so downstream tests
        # treat them as immediates / pads.
        accesses = tuple("CS_AC_IGNORE" if a == "0" else a
                         for (_t, a) in ops_data)
        operand_types = tuple(t for (t, _a) in ops_data)
        internal = m.group("internal")
        ir, iw = implicit.get(internal, (0, 0))
        variants.append(CapVariant(
            internal=internal,
            canonical=m.group("canonical"),
            accesses=accesses,
            operand_types=operand_types,
            n_implicit_reads=ir,
            n_implicit_writes=iw,
        ))
    return variants


def parse_x86_mapping_insn_op(text: str,
                              implicit: dict[str, tuple[int, int]] | None = None
                              ) -> list[CapVariant]:
    """Parse X86MappingInsnOp.inc into a list of CapVariant.

    The file is a 75-Klines array of designated initialisers, each of
    the form:
        { /\\* X86_<internal>, X86_INS_<canonical>: <asm> *\\/
            <eflags-or-0>,
            { CS_AC_<flag>, CS_AC_<flag>, ..., 0 }
        },

    @implicit maps internal-name → (n_implicit_reads, n_implicit_writes)
    derived from X86MappingInsn.inc.  Missing entries default to
    (0, 0).
    """
    entry_re = re.compile(
        r"\{\s*/\*\s*(?P<internal>X86_[A-Za-z0-9_]+),\s*"
        r"(?P<canonical>X86_INS_[A-Za-z0-9_]+):[^*]*\*/\s*"
        r"[^,]+,\s*"                                     # eflags (not used)
        r"\{\s*(?P<ops>[^}]*)\}\s*\}",
        re.DOTALL,
    )
    implicit = implicit or {}
    variants: list[CapVariant] = []
    for m in entry_re.finditer(text):
        ops_raw = m.group("ops").strip()
        parts = [p.strip() for p in ops_raw.split(",") if p.strip()]
        # Last entry is always "0" sentinel.
        if parts and parts[-1] == "0":
            parts.pop()
        internal = m.group("internal")
        # Derive per-operand types from the variant name suffix.  The
        # x86 mapping file doesn't store CS_OP_* per operand (only
        # CS_AC_*), but LLVM/Capstone encode the operand-type pattern
        # in the variant name (the "rr" / "rm" / "mr" / "ri" / "mi"
        # tail).  parse_suffix_tokens returns a sequence aligned with
        # the access list when the shape is recognised; if not, we
        # leave operand_types empty and the classifier will not be
        # able to disambiguate W+R+R-style stores from W+R+R
        # arithmetic — same as before this field was added.
        suffix = _suffix_after_mnemonic(internal, m.group("canonical"))
        tokens = parse_suffix_tokens(suffix)
        operand_types = tuple(tokens) if tokens else ()
        if len(operand_types) != len(parts):
            # Suffix and access lists disagree on operand count —
            # leave the types empty rather than mis-pair them.
            operand_types = ()
        ir, iw = implicit.get(internal, (0, 0))
        variants.append(CapVariant(
            internal=internal,
            canonical=m.group("canonical"),
            accesses=tuple(parts),
            operand_types=operand_types,
            n_implicit_reads=ir,
            n_implicit_writes=iw,
        ))
    return variants


def _suffix_after_mnemonic(internal: str, canonical: str) -> str:
    """Strip the leading 'X86_<MNEM><BITWIDTH>' prefix from the
    internal name to expose the operand-shape suffix.  Returns the
    tail (e.g. 'rr', 'rm', 'mr', 'ri', 'mi', 'i16', 'ao16', '')."""
    mnem = canonical.removeprefix("X86_INS_")
    body = internal.removeprefix("X86_")
    if body.startswith(mnem):
        body = body[len(mnem):]
    # Strip leading bit-width tags (8 / 16 / 32 / 64 / 128 / 256 /
    # 512) that LLVM/Capstone embed.  Loop to peel multiple if any.
    body = re.sub(r"^(?:8|16|32|64|128|256|512)+", "", body)
    return body


# Parse the operand-shape suffix into a sequence of operand tokens.
# The tokens map to the walker's view: r=register, m=memory, i=imm.
# Unrecognised suffixes return None so the variant gets flagged
# rather than misclassified.
_SUFFIX_TOKEN_MAP: dict[str, tuple[str, ...]] = {
    # Common arithmetic / mov forms
    "":      (),                  # no explicit operands (implicit-only)
    "r":     ("r",),
    "m":     ("m",),
    "i":     ("i",),
    "rr":    ("r", "r"),
    "rm":    ("r", "m"),
    "mr":    ("m", "r"),
    "ri":    ("r", "i"),
    "mi":    ("m", "i"),
    "rri":   ("r", "r", "i"),
    "rrm":   ("r", "r", "m"),
    "rmi":   ("r", "m", "i"),
    "rmr":   ("r", "m", "r"),
    "mri":   ("m", "r", "i"),
    "rrr":   ("r", "r", "r"),
    "rrri":  ("r", "r", "r", "i"),
    "rrrr":  ("r", "r", "r", "r"),
}


def _normalize_suffix(suffix: str) -> str:
    """Reduce a variant suffix to its core shape token set.

    Capstone/LLVM decorate internal-name suffixes with bit-width
    annotations and microarchitectural tags that don't affect the
    walker's view of operand types.  Strip them so the lookup in
    _SUFFIX_TOKEN_MAP succeeds for the common shape families:
      - rr8  / rm16   / mi32     →  rr / rm / mi  (operand size)
      - rr_REV / mr_NOREX        →  rr / mr       (microarch tags)
      - i8 / i16 / i32 / i64     →  i             (imm width)
    """
    s = suffix
    # Strip trailing _TAG (e.g. _REV, _NOREX, _alt, _NOREX_REV).
    s = re.sub(r"(?:_[A-Z][A-Za-z0-9]*)+\Z", "", s)
    # Drop trailing bit-width digits (after a token letter): r/m/i + N.
    s = re.sub(r"([rmi])(?:8|16|32|64|128|256|512)+", r"\1", s)
    # Standalone leading width: i8 / i16 → 'i' (already handled by the
    # above when there's a preceding letter; for the bare 'i' case the
    # match still works since the digit isn't required).
    return s


def parse_suffix_tokens(suffix: str) -> tuple[str, ...] | None:
    """Return the per-operand token sequence for a variant suffix.

    Recognises only the common shapes; returns None for the rest so
    the classifier flags those variants instead of guessing.
    """
    return _SUFFIX_TOKEN_MAP.get(_normalize_suffix(suffix))


# Constants describing the per-op CS_AC_ access bitfields.  Each
# variant's accesses tuple holds expressions like "CS_AC_WRITE",
# "CS_AC_READ", or "CS_AC_READ | CS_AC_WRITE".  Pure CS_AC_IGNORE
# (immediates) doesn't matter for shape — the imm is signalled by
# the suffix token, not the access bits.
def _is_rmw(access_expr: str) -> bool:
    return "READ" in access_expr and "WRITE" in access_expr


def _is_write(access_expr: str) -> bool:
    return "WRITE" in access_expr


def derive_walker_shape(variant: CapVariant,
                        include_implicit_regs: bool) -> WalkerShape | None:
    """Compute the runtime shape the QEMU operand walker would
    produce for @variant.  Returns None when we can't statically
    derive it (unrecognised suffix or operand-count mismatch); the
    classifier treats None as "shape unknown → row uncoverable".

    When @include_implicit_regs is true (x86 + aarch64), Capstone's
    regs_read[] / regs_write[] arrays are folded into n_src_regs /
    n_dst_regs to match how the walker behaves at template build —
    an implicit EFLAGS read on ADOX/CMOV/etc. adds a hidden src.
    """
    suffix = _suffix_after_mnemonic(variant.internal, variant.canonical)
    tokens = parse_suffix_tokens(suffix)
    if tokens is None:
        return None
    # Variants with mismatched (accesses, tokens) lengths get rejected
    # — the table has a few oddballs where the comment claims an
    # operand count that the access array doesn't agree with.
    if len(tokens) != len(variant.accesses):
        return None

    n_src_regs = 0
    n_dst_regs = 0
    max_dep_loads = 0
    max_dep_stores = 0
    has_imm = False
    value_src_origin = "none"
    for tok, acc in zip(tokens, variant.accesses):
        if tok == "r":
            if _is_rmw(acc):
                n_src_regs += 1
                n_dst_regs += 1
            elif _is_write(acc):
                n_dst_regs += 1
            else:  # pure READ
                n_src_regs += 1
                if value_src_origin == "none":
                    value_src_origin = "first"
                else:
                    value_src_origin = "last"
        elif tok == "m":
            # MEM operand contributes its base+index regs as srcs.
            # We can't know statically how many addressing-mode regs
            # the encoding actually has; for shape-bucketing purposes
            # we approximate by treating "could be 0..2".  The exact
            # count doesn't change the dep_passthrough decision —
            # what matters is whether mem is load (READ access) or
            # store (WRITE access) or RMW.
            if _is_rmw(acc):
                max_dep_loads += 1
                max_dep_stores += 1
            elif _is_write(acc):
                max_dep_stores += 1
            else:  # pure READ
                max_dep_loads += 1
                if value_src_origin == "none":
                    value_src_origin = "load"
        elif tok == "i":
            has_imm = True
            if value_src_origin == "none":
                value_src_origin = "imm"

    if include_implicit_regs:
        # The walker appends implicit reads/writes to src_regs /
        # dst_regs AFTER the explicit operand pass.  We don't track
        # the exact slot order beyond "value_src_origin" so for
        # classification purposes we just bump the counts; any non-
        # zero implicit set will fail the single-input shape check
        # in shape_fits_dep_passthrough.
        n_src_regs += variant.n_implicit_reads
        n_dst_regs += variant.n_implicit_writes

    return WalkerShape(
        n_src_regs=n_src_regs,
        n_dst_regs=n_dst_regs,
        max_dep_loads=max_dep_loads,
        max_dep_stores=max_dep_stores,
        has_imm=has_imm,
        value_src_origin=value_src_origin,
    )


def shape_fits_dep_passthrough(shape: WalkerShape) -> bool:
    """True iff dep_passthrough produces correct masks for @shape.

    The behavior group is single-value-input → single-output.  Any
    RMW operand, multiple inputs, or fan-out disqualifies.
    """
    # rr-form: one reg src, one reg dst
    if (shape.n_src_regs == 1 and shape.n_dst_regs == 1 and
            shape.max_dep_loads == 0 and shape.max_dep_stores == 0 and
            not shape.has_imm):
        return True
    # rm-form: load → reg dst (addressing-mode regs are tolerated)
    if (shape.n_dst_regs == 1 and shape.max_dep_loads == 1 and
            shape.max_dep_stores == 0 and not shape.has_imm):
        return True
    # ri-form: imm → reg dst, no other srcs
    if (shape.n_src_regs == 0 and shape.n_dst_regs == 1 and
            shape.max_dep_loads == 0 and shape.max_dep_stores == 0 and
            shape.has_imm):
        return True
    # mr-form: reg → store (addressing-mode regs tolerated)
    if (shape.n_dst_regs == 0 and shape.max_dep_stores == 1 and
            shape.max_dep_loads == 0 and not shape.has_imm and
            shape.value_src_origin == "last"):
        return True
    # mi-form: imm → store
    if (shape.n_dst_regs == 0 and shape.max_dep_stores == 1 and
            shape.max_dep_loads == 0 and shape.has_imm):
        return True
    return False


# Per-ISA properties for the classifier.  Must stay in sync with
# `isa_properties[]` in champsim_tracer_mnemonics.h — same boolean,
# different layer.  Defaults are false so unknown ISAs can't trip a
# misleading classification.
ISA_INCLUDES_IMPLICIT_REGS: dict[str, bool] = {
    "x86":     True,
    "aarch64": True,
    "riscv":   False,
    "mips":    False,
}


# Per-ISA Capstone-source layout descriptors.  Maps the audit's
# normalised ISA key to the directory + file names + internal/canonical
# prefix conventions.  x86 uses the legacy flat layout; the others use
# the "modern" GenCSMapping* layout.
_CAPSTONE_LAYOUTS: dict[str, dict] = {
    "x86": {
        "style": "legacy",
        "dir": "X86",
        "insn":     "X86MappingInsn.inc",
        "insn_op":  "X86MappingInsnOp.inc",
        "internal_prefix_insn":    "X86_",
        "internal_prefix_insn_op": "X86_",
        "ins_prefix":              "X86_INS_",
    },
    # The "modern" Capstone Gen* layout uses inconsistent casing for
    # the per-arch internal prefix between Insn.inc (preserves LLVM's
    # original CamelCase or PascalCase) and InsnOp.inc (uppercased).
    # We carry both prefixes so each file matches its own regex.
    "aarch64": {
        "style": "modern",
        "dir": "AArch64",
        "insn":     "AArch64GenCSMappingInsn.inc",
        "insn_op":  "AArch64GenCSMappingInsnOp.inc",
        "internal_prefix_insn":    "AArch64_",
        "internal_prefix_insn_op": "AARCH64_",
        "ins_prefix":              "AARCH64_INS_",
    },
    "riscv": {
        "style": "modern",
        "dir": "RISCV",
        "insn":     "RISCVGenCSMappingInsn.inc",
        "insn_op":  "RISCVGenCSMappingInsnOp.inc",
        "internal_prefix_insn":    "RISCV_",
        "internal_prefix_insn_op": "RISCV_",
        "ins_prefix":              "RISCV_INS_",
    },
    "mips": {
        "style": "modern",
        "dir": "Mips",
        "insn":     "MipsGenCSMappingInsn.inc",
        "insn_op":  "MipsGenCSMappingInsnOp.inc",
        "internal_prefix_insn":    "Mips_",
        "internal_prefix_insn_op": "MIPS_",
        "ins_prefix":              "MIPS_INS_",
    },
}


@lru_cache(maxsize=None)
def _capstone_variants(isa: str) -> tuple[CapVariant, ...]:
    """Load and cache the per-variant Capstone table for @isa."""
    layout = _CAPSTONE_LAYOUTS.get(isa)
    if layout is None:
        return tuple()
    arch_dir   = CAPSTONE_ARCH_DIR / layout["dir"]
    insn_path  = arch_dir / layout["insn"]
    op_path    = arch_dir / layout["insn_op"]
    if not (insn_path.is_file() and op_path.is_file()):
        return tuple()
    if layout["style"] == "legacy":
        implicit = _parse_x86_mapping_insn_implicit(insn_path.read_text())
        return tuple(parse_x86_mapping_insn_op(op_path.read_text(), implicit))
    # "modern" layout, shared across aarch64 / riscv / mips.  Each
    # file uses its own internal-name casing; bridge them by mapping
    # both into the InsnOp-side prefix so the resulting dict keys
    # match between the two passes.
    insn_text = insn_path.read_text()
    implicit_raw = _parse_modern_mapping_insn_implicit(
        insn_text,
        layout["internal_prefix_insn"], layout["ins_prefix"],
    )
    case_a = layout["internal_prefix_insn"]
    case_b = layout["internal_prefix_insn_op"]
    if case_a != case_b:
        implicit = {
            case_b + k.removeprefix(case_a): v
            for k, v in implicit_raw.items()
        }
    else:
        implicit = implicit_raw
    return tuple(_parse_modern_mapping_insn_op(
        op_path.read_text(),
        layout["internal_prefix_insn_op"], layout["ins_prefix"],
        implicit,
    ))


@lru_cache(maxsize=None)
def _variants_by_canonical(isa: str) -> dict[str, tuple[CapVariant, ...]]:
    """Group cached variants by canonical X86_INS_<name>."""
    out: dict[str, list[CapVariant]] = {}
    for v in _capstone_variants(isa):
        out.setdefault(v.canonical, []).append(v)
    return {k: tuple(v) for k, v in out.items()}


# No default refiner.
#
# A row without .dep_refine publishes no dependency block, and the format
# defines that absence as the all-to-all over-approximation (docs/format.rst:
# "Absence of CST_INSN_FLAG_HAS_DEP_BLOCK is the implicit all-to-all
# over-approximation").  dep_all_to_all wrote that same over-approximation
# out explicitly, so every row carrying it spent bytes restating the reader's
# own default -- measured INERT on 48,179 of 48,179 decodes across four ISAs
# and two workloads (cst_runs/p3/arc3/w11/VERDICT.md).  There is nothing for a
# fallback to be, so there is no fallback.
DEFAULT_DEP_REFINE = None


def _count_access(variant: CapVariant, include_implicit: bool
                  ) -> tuple[int, int, bool]:
    """Return (n_src, n_dst, has_imm) for an access list.

    RMW operands count toward both src and dst.  Implicit reg
    reads/writes (per X86MappingInsn.inc's `regs_read[]` /
    `regs_write[]`) fold in when the ISA's walker enables them.
    """
    n_src = 0
    n_dst = 0
    has_imm = False
    for a in variant.accesses:
        is_w = "WRITE" in a
        is_r = "READ"  in a
        if a == "CS_AC_IGNORE":
            has_imm = True
            continue
        if is_r: n_src += 1
        if is_w: n_dst += 1
    if include_implicit:
        n_src += variant.n_implicit_reads
        n_dst += variant.n_implicit_writes
    return n_src, n_dst, has_imm


def access_fits_dep_passthrough(variant: CapVariant,
                                include_implicit: bool) -> bool:
    """Test whether a single Capstone variant's access pattern is
    inside dep_passthrough's behavior group.

    dep_passthrough's runtime invariant is "exactly one output (reg
    dst OR mem store) consuming at most one value input (reg src,
    load_data, or immediate), with zero or more address-mode regs
    when the output is a memory store."  We don't care which r/m/i
    the operand types are — the refiner's internal dispatch handles
    every combination — but the audit DOES need to distinguish mr
    forms (1W on a MEM operand + 1R on a REG + optional address-mode
    REGs as CS_AC_READ) from rrr arithmetic (1W on a REG + 2R on
    REGs); they share access pattern (W, R, R) so a count-only test
    can't separate them.  CapVariant.operand_types carries the
    per-operand CS_OP_* kinds from Capstone's source tables exactly
    for this purpose; consult them whenever the access count would
    otherwise be ambiguous.

    Accepted shapes:
      - (1W, 1R) no RMW / no imm:   rr / rm form, write on REG or MEM.
      - (1W, 0R) + imm:             ri / mi form.
      - (1W, 1R) RMW:               legacy unary RMW (BSWAP/NOT).
      - (1W, 2R) no imm, write-op is MEM, no RMW:
          mr-form store — the WRITE goes to memory and at most one of
          the READs is the value, the rest are addressing-mode regs.
      - (1W, 3R) no imm, write-op is MEM, no RMW:
          mr-form store with base + index addressing.

    Implicit regs folded by include_implicit count toward n_src /
    n_dst exactly as before.
    """
    has_rmw = any(("READ" in a) and ("WRITE" in a)
                  for a in variant.accesses)
    n_src, n_dst, has_imm = _count_access(variant, include_implicit)
    if n_dst != 1:
        return False
    if has_rmw:
        if n_src == 1 and not has_imm:
            return True  # unary RMW (BSWAP / NOT / etc.).
        return False
    if n_src == 1 and not has_imm:
        return True
    if n_src == 0 and has_imm:
        return True
    if 1 <= n_src <= 3 and not has_imm:
        # Disambiguate mr-form store from rrr arithmetic by the
        # operand types: the WRITE must be on a MEM operand for mr
        # to apply.
        write_idx = next((i for i, a in enumerate(variant.accesses)
                          if "WRITE" in a), -1)
        if write_idx < 0 or write_idx >= len(variant.operand_types):
            return False
        if variant.operand_types[write_idx] in _MEM_OPERAND_TYPES:
            return True
    return False


def access_fits_dep_all_to_all(variant: CapVariant,
                               include_implicit: bool) -> bool:
    """Affirmative test for dep_all_to_all (vs. defaulting to it).

    dep_all_to_all is the right refiner in any of these cases:

      * No explicit outputs (n_dst == 0):
          Branches, scatter-stores, and other ops Capstone tags with
          all-CS_AC_READ.  At runtime, dep_all_to_all is correct
          regardless of whether the walker sees an output: it emits
          a real mask when there is one, or bails harmlessly when
          there isn't.  Affirmative classification.
      * ≥1 output AND total_inputs == 0:
          Constant-writer (CLC, STC, RDTSC, CPUID, ...).  Each
          output depends on nothing; dep_all_to_all emits an empty
          mask for each.
      * ≥1 input AND ≥1 output, with multiple inputs / multiple
        outputs / an RMW operand:
          Genuine fan-in.  Every output depends on every input.

    The one case we *reject* here is single-in single-out (no RMW)
    — that belongs to dep_passthrough.
    """
    has_rmw = any(("READ" in a) and ("WRITE" in a) for a in variant.accesses)
    n_src, n_dst, has_imm = _count_access(variant, include_implicit)
    total_inputs = n_src + (1 if has_imm else 0)
    if n_dst == 0:
        return True
    if total_inputs == 0:
        return True
    if total_inputs == 1 and n_dst == 1 and not has_rmw:
        return False
    return True


def _is_nop_variant(variant: CapVariant, include_implicit: bool) -> bool:
    """True for variants with no inputs and no outputs — NOP-class
    instructions that have no architectural dataflow at all.
    dep_all_to_all is correct (and a runtime no-op) for them; we
    mark them affirmative in the audit since the classification is
    deliberate, not a precision gap."""
    n_src, n_dst, has_imm = _count_access(variant, include_implicit)
    return n_src == 0 and n_dst == 0 and not has_imm


def _is_degenerate_variant(variant: CapVariant) -> bool:
    """Some Capstone internal variants carry under-populated access
    lists — for example, RISC-V's base SB/SD/FSD/etc. have a single
    CS_AC_READ entry where the Pseudo-prefixed sibling has the full
    (W, R, R) operand list.  These under-tagged entries don't reflect
    runtime semantics (QEMU sees the actual decoded operand list at
    trace time) and would otherwise force the whole canonical into
    the fallback bucket.  Detect them so the classifier can ignore
    them while still respecting their well-formed sibling variants.

    Two shapes count as degenerate:

      * Store-side under-tagging: a single CS_AC_READ entry with
        n_dst == 0, no immediate, no implicit writes — the
        "underspecified store" pattern (RISC-V SB/SD base variants,
        MIPS SD/SW Macro siblings).
      * Load-side under-tagging: a single CS_AC_WRITE entry with
        n_src == 0, no immediate, no implicit reads — the
        "underspecified load" pattern (RISC-V LD/SW base variants
        where the well-formed Pseudo* sibling carries the MEM read
        operand).  A real "writes a register, reads nothing"
        instruction (CPUID, RDTSC) would have implicit reads, so
        gating on n_implicit_reads == 0 keeps those classified.
    """
    n_src, n_dst, has_imm = _count_access(variant, False)
    if len(variant.accesses) > 1:
        return False
    if has_imm:
        return False
    # Store-side under-tagging.
    if (n_dst == 0 and n_src > 0
            and variant.n_implicit_writes == 0):
        return True
    # Load-side under-tagging.
    if (n_src == 0 and n_dst > 0
            and variant.n_implicit_reads == 0):
        return True
    return False


def classify_dep_refine_explicit(info: IsaInfo, const_name: str,
                                 entry: Entry) -> tuple[str, bool]:
    """Pick a .dep_refine name and report whether the assignment is
    affirmative (classifier has positive evidence) or a fallback
    (classifier couldn't decide; we still write dep_all_to_all so
    the row carries an explicit refiner, but the audit counts it as
    a precision gap).

    Returns (refiner_name, affirmative).
    Priority:
      1. Per-ISA hand-curated override lists (address-compute mnemonics
         Capstone can't distinguish from real loads).  Affirmative.
      2. Access-pattern shape classifier — dep_passthrough when every
         variant is single-input single-output, then dep_all_to_all
         when every variant has multiple inputs / outputs / RMW (the
         genuine all-to-all behavior group).  Both affirmative.
      3. Default catch-all `dep_all_to_all` for everything else.
         Non-affirmative — surfaces in the audit's precision-gap
         list grouped by GenericOpcode.
    """
    del entry  # not consulted; classification is pure Capstone-driven

    # 1. Hand-curated per-ISA override lists.
    # dep_lea exists to UNDO a phantom load slot: Capstone tags x86 LEA's
    # MEM operand CS_AC_READ, so the operand walk counts a load that never
    # fires.  AArch64 ADR/ADRP and RISC-V AUIPC carry no MEM operand at all,
    # so there is nothing to undo and the refiner republishes the default --
    # measured inert on 1,732 of 1,732 decodes of those three rows.  Bind it
    # only where the defect it repairs is present.
    if const_name in ISA_ADDRESS_COMPUTE_INSNS.get(info.key, set()):
        if info.key in ISA_ADDRESS_COMPUTE_PHANTOM_LOAD:
            return ("dep_lea", True)
        # PINNED UNBOUND rather than left to fall through.  The shape
        # classifier would promote ADR/ADRP/AUIPC to dep_passthrough, and
        # that is a NEW claim rather than the removal this change is; the
        # row keeps the over-approximation it already published.
        return (None, True)
    if const_name in ISA_STACK_PUSH_INSNS.get(info.key, set()):
        return ("dep_x86_stack_push", True)
    if const_name in ISA_STACK_POP_INSNS.get(info.key, set()):
        return ("dep_x86_stack_pop", True)
    # The two structured-vector LOAD refiners and the interleaved STORE
    # refiner are gone.  They were written against a slot model the wire does
    # not have: each needed max_dep_loads (or max_dep_stores) to be a multiple
    # of the register count, i.e. one slot per element access.  The wire's
    # slots count static memory OPERANDS -- docs/format.rst 4.5, "AArch64
    # ld4 {v0.16b-v3.16b}, [x1] is one operand publishing 64 memops" -- so a
    # structured access arrives with exactly ONE slot and the precondition
    # cannot hold for any multi-register form.  Measured over every LD1/LD2/
    # LD3/LD4 and ST2/ST3/ST4 shape on AArch64 NEON and SVE and every
    # vlseg/vlsseg/vluxseg/vloxseg and vsseg/vsuxseg/vsoxseg form on RISC-V:
    # 61 of 61 decodes bailed, on both ISAs, in every register count.
    #
    # dep_vec_struct_store survives because its precondition is on the VALUE
    # sources rather than on the slot count, and a single-register ST1 form
    # satisfies it: it names the stored register and not the address register
    # as the datum, which is an edge the default does not have.
    if const_name in ISA_VEC_STRUCT_SEQUENTIAL_STORE_INSNS.get(info.key,
                                                                set()):
        return ("dep_vec_struct_store", True)
    # PINNED UNBOUND, for the same reason.  Measured: letting these 83 rows
    # reach the shape classifier promotes them to dep_passthrough, whose
    # rm-form rule states dst = load_data[0] -- and on an SVE predicated load
    # that DROPS the governing predicate and the FP-enable the old refiner's
    # over-approximation carried.  `ld1b {z0.b}, p0/z, [x0]` went from
    #   %v0{0}=[%p0,%sysfpen,ld0]   to   %v0{0}=[ld0]
    # in the decoded trace: a MISSED dependency, and one R7 convicts
    # directly, since a pending write to p0 must resolve before the load may
    # proceed.  Unbound, the row keeps what it published before.
    if (const_name in ISA_VEC_STRUCT_SEQUENTIAL_LOAD_INSNS.get(info.key,
                                                               set())
            or const_name in ISA_VEC_STRUCT_INTERLEAVED_LOAD_INSNS.get(
                info.key, set())
            or const_name in ISA_VEC_STRUCT_INTERLEAVED_STORE_INSNS.get(
                info.key, set())):
        return (None, True)
    if const_name in ISA_DEP_PASSTHROUGH_LOAD_INSNS.get(info.key, set()):
        return ("dep_passthrough", True)
    if const_name in ISA_DEP_PASSTHROUGH_STORE_INSNS.get(info.key, set()):
        return ("dep_passthrough", True)

    variants = _variants_by_canonical(info.key).get(const_name)
    if not variants:
        return (DEFAULT_DEP_REFINE, False)
    include_implicit = ISA_INCLUDES_IMPLICIT_REGS.get(info.key, False)

    # 2. Filter out variants Capstone under-tagged.  Includes phantom
    # multibyte-NOP variants (a CS_AC_READ on an operand that's
    # ignored by the CPU) and Pseudo-* siblings whose access list is
    # missing operands.  Their well-formed sibling variants carry the
    # real semantics; the classifier follows those.
    informative = [v for v in variants if not _is_degenerate_variant(v)]
    if not informative:
        # All variants are degenerate single-access shapes — Capstone
        # under-tags the canonical uniformly (MIPS LW / SW and their
        # microMIPS / DSP siblings are the canonical example).  The
        # runtime walker still sees the actual operand list from
        # QEMU's per-execution detail, so dep_passthrough applies
        # precisely when the access direction is uniform:
        #
        #   every variant is single CS_AC_WRITE → rm-form load
        #     (one mem-read produces one reg-write; dst depends on
        #     load_data[0]).
        #   every variant is single CS_AC_READ  → mr-form store
        #     (one reg-read drives one mem-write; store_data depends
        #     on the value src).
        #
        # When the access direction is mixed across variants we keep
        # dep_all_to_all as the conservative-correct fallback.
        only_write = all(set(v.accesses) == {"CS_AC_WRITE"}
                         for v in variants)
        only_read = all(set(v.accesses) == {"CS_AC_READ"}
                        for v in variants)
        # Gate on operand types: the under-tagged load/store shape
        # this fallback exists for always carries at least one
        # register or memory operand (the data reg + the [base+disp]
        # MEM that Capstone happens to drop the access tag on).
        # Without that gate, single-CS_AC_READ branch insns whose
        # only operand is an IMM target (MIPS `b target`, `bc`,
        # `bposge32`, ...) get mis-promoted to dep_passthrough.
        has_reg_or_mem_operand = any(
            t in _REG_OR_MEM_OPERAND_TYPES
            for v in variants for t in v.operand_types
        )
        if (only_write or only_read) and has_reg_or_mem_operand:
            return ("dep_passthrough", True)
        return (DEFAULT_DEP_REFINE, True)

    # 3. NOP-class: every (informative) variant has zero inputs AND
    # zero outputs.  dep_all_to_all is a runtime no-op for them;
    # mark the row affirmative so the audit doesn't treat it as a
    # precision gap.
    if all(_is_nop_variant(v, include_implicit) for v in informative):
        return (DEFAULT_DEP_REFINE, True)

    # 4. Passthrough behavior group (precise) when every informative
    # variant fits.  Mixed canonicals (e.g. KMOV-family where one of
    # five variants has a Capstone-mistagged access list) fall
    # through to dep_all_to_all — runtime behaviour is correct
    # either way, but dep_all_to_all is the safe conservative
    # choice when not all variants match passthrough's shape.
    if all(access_fits_dep_passthrough(v, include_implicit) for v in informative):
        return ("dep_passthrough", True)

    # 5. Affirmative all-to-all.  Once we've filtered degenerate
    # variants and ruled out passthrough, dep_all_to_all is
    # affirmatively correct for every remaining shape — it emits
    # precise masks when the runtime walker sees real outputs and
    # bails harmlessly when it doesn't.  Mark this affirmative so
    # the audit doesn't treat mixed-but-classified canonicals as
    # precision gaps.
    return (DEFAULT_DEP_REFINE, True)


def classify_dep_refine(info: IsaInfo, const_name: str,
                        entry: Entry) -> str:
    """Backward-compatible classifier — returns only the refiner name,
    discarding the affirmative-vs-fallback flag.  generated_body uses
    this; audit_one calls the explicit variant for accounting."""
    return classify_dep_refine_explicit(info, const_name, entry)[0]


# ----- Per-ISA lane classification --------------------------------
#
# Lane info is per-Capstone-insn-id (not per-GenericOpcode) so we can
# distinguish element-wise VADDPS from horizontal VHADDPS — the
# generic category lumps both as VEC_*.  The classifier combines two
# signals:
#
#   (a) Capstone-derived "is this a vec op at all?": variant.internal
#       names carry reg-width markers (Y for YMM, Z for ZMM on x86,
#       arrangement specifiers on aarch64, V-reg references on
#       RISC-V V, .b/.h/.w/.d suffixes on MIPS MSA).  If no variant
#       uses a vector reg, the canonical isn't a vec op.
#
#   (b) Name-pattern match for the parallel-vs-cross axis: Capstone
#       doesn't structurally distinguish element-wise arith from
#       shuffles / broadcasts / horizontal reductions, so we match
#       canonical-name prefixes against curated cross-lane sets.
#       Anything not in the cross set defaults to parallel.

# X86 Capstone variant tokens that signal a vector-context insn.
# Multiple sources:
#   - AVX widths embedded in variant.internal:  YMM/ZMM/Z128/Z256
#     (legacy VEX YMM forms also appear as bare "Y<suffix>")
#   - MMX prefix on the variant.internal:        "MMX_"
#   - SSE legacy forms have no width marker in the variant name
#     (XMM is implied), so we also accept variants whose canonical
#     mnemonic starts with one of the SSE/SSE2/SSE3/SSSE3/SSE4 vec
#     opcode prefixes.  Each prefix below uniquely names a vector
#     family — none of them shadow a scalar-int insn.
X86_VARIANT_VEC_MARKERS: tuple[str, ...] = (
    "YMM", "ZMM", "Z128", "Z256",
    "MMX_",
)
X86_SSE_LEGACY_MNEM_PREFIXES: tuple[str, ...] = (
    # Legacy SSE/SSE2 packed FP/int — operand class is XMM by definition.
    "ADDPS", "ADDPD", "ADDSS", "ADDSD",
    "SUBPS", "SUBPD", "SUBSS", "SUBSD",
    "MULPS", "MULPD", "MULSS", "MULSD",
    "DIVPS", "DIVPD", "DIVSS", "DIVSD",
    "SQRTPS", "SQRTPD", "SQRTSS", "SQRTSD",
    "RSQRTPS", "RSQRTSS", "RCPPS", "RCPSS",
    "MAXPS", "MAXPD", "MINPS", "MINPD",
    "MAXSS", "MAXSD", "MINSS", "MINSD",
    "ANDPS", "ANDPD", "ANDNPS", "ANDNPD",
    "ORPS",  "ORPD",  "XORPS", "XORPD",
    "MOVAPS", "MOVAPD", "MOVUPS", "MOVUPD",
    "MOVSS",  "MOVSD",
    "MOVLPS", "MOVLPD", "MOVHPS", "MOVHPD",
    "MOVLHPS", "MOVHLPS",
    "MOVDQA", "MOVDQU",
    "MOVDDUP", "MOVSHDUP", "MOVSLDUP",
    "MOVNTPS", "MOVNTPD", "MOVNTDQ",
    "CMPPS", "CMPPD", "CMPSS", "CMPSD",
    "SHUFPS", "SHUFPD",
    "UNPCKLPS", "UNPCKLPD", "UNPCKHPS", "UNPCKHPD",
    "CVT",            # CVTPS2PD, CVTPD2DQ, etc. — many subforms
    "BLENDPS", "BLENDPD", "BLENDVPS", "BLENDVPD",
    "DPPS", "DPPD",
    "INSERTPS", "EXTRACTPS",
    "HADDPS", "HADDPD", "HSUBPS", "HSUBPD",
    "ROUNDPS", "ROUNDPD", "ROUNDSS", "ROUNDSD",
    # SSE/SSE2 packed integer — the "P*" family.  These ALL operate
    # on XMM (or MMX); none of them shadow GPR ops.
    "PADD", "PSUB", "PMUL", "PCMPEQ", "PCMPGT", "PCMPESTR", "PCMPISTR",
    "PMIN", "PMAX", "PABS", "PSIGN", "PAVG", "PSAD",
    "PAND", "POR", "PXOR", "PANDN",
    "PSLL", "PSRL", "PSRA",
    "PSHUF", "PSHUFB", "PSHUFLW", "PSHUFHW", "PSHUFD",
    "PALIGNR", "PSLLDQ", "PSRLDQ",
    "PBLEND", "PINSR", "PEXTR", "PMOV",
    "PUNPCK", "PACKS", "PACKU",
    "PMADDWD", "PMADDUBSW",
    "PCLMUL",
    "AES",
)

X86_CROSS_LANE_PREFIXES: tuple[str, ...] = (
    "VPSHUF", "PSHUF",
    "VBROADCAST", "VPBROADCAST",
    "VPERM", "VPERMI2", "VPERMT2",
    "VPPERM",          # XOP 2-source byte permute (not a VPERM* form)
    "VHADD", "VHSUB", "HADD", "HSUB",
    "VPHADD", "VPHSUB", "PHADD", "PHSUB",
    "VEXTRACT", "VINSERT",
    "VPEXTR", "VPINSR", "PEXTR", "PINSR",
    "VPMOVSX", "VPMOVZX", "PMOVSX", "PMOVZX",
    "VPACKS", "VPACKU", "PACKS", "PACKU",
    "VUNPCK", "PUNPCK", "VPUNPCK",
    "VPSADBW", "PSADBW",
    "VDPPS", "VDPPD", "DPPS", "DPPD",
    "VPMADDWD", "PMADDWD",
    "VPMADDUBSW", "PMADDUBSW",
)


def classify_x86_lane(const_name: str,
                      variants: tuple) -> tuple[str, bool] | None:
    name = const_name.removeprefix("X86_INS_")
    # (a) Capstone variant gate: AVX/EVEX width markers,
    #     MMX_ prefix, or AVX V<mnemonic>...  (canonical names
    #     starting with "V" cover the entire AVX/EVEX family).
    has_variant_vec_marker = any(
        any(m in v.internal for m in X86_VARIANT_VEC_MARKERS) or
        v.internal.startswith("X86_V")
        for v in variants
    )
    # (b) Legacy SSE/MMX fallback: variants carry no width marker
    #     (XMM is implied) but the canonical mnemonic itself
    #     uniquely names a vector family.
    has_legacy_sse_mnem = any(
        name.startswith(p) for p in X86_SSE_LEGACY_MNEM_PREFIXES
    )
    if not (has_variant_vec_marker or has_legacy_sse_mnem):
        return None
    # (c) parallel-vs-cross axis from canonical-name prefixes.
    for p in X86_CROSS_LANE_PREFIXES:
        if name.startswith(p):
            return ("LANE_MASK_KIND_STATIC", False)
    return ("LANE_MASK_KIND_STATIC", True)


# aarch64 — Capstone variant-name vector markers.  Tokens are
# anchored so they cannot be confused with the constant "H64" inside
# the "AARCH64_" prefix.
#   - NEON shape: lowercase v<count><lane-letter><width>, e.g.
#     ADDv8i8, FADDv4f32, PMULLv1i64.  Capstone never emits a
#     lowercase v inside a non-NEON mnemonic, so no leading anchor
#     is needed (verified across the AArch64 canonical-variant set).
#   - NEON lane-indexed access: vi<width>, e.g. INSvi16gpr,
#     UMOVvi16, SHLv16i8_shift (the latter is also caught by the
#     v\d+i token above).
#   - SVE / SME: variant ends in _<B|H|S|D> (lane element width).
#   - SVE Z/P register references: tokens _ZZ, _ZP, _PP in the
#     variant name.
AARCH64_VEC_VARIANT_RES = (
    re.compile(r"v\d+[ifu]"),
    re.compile(r"vi\d+"),
    re.compile(r"_[BHSD]$"),
    re.compile(r"_(ZZ|ZP|PP)"),
)


# Canonical-name fallback: instructions whose Capstone variant.internal
# doesn't carry a NEON shape token but which the AArch64 manual
# defines as vector-class (writes Z/P/V or operates on V/Z/P operands).
# Each prefix here uniquely names a vector mnemonic family — none
# shadows a scalar-int op.
AARCH64_VEC_NAME_PREFIXES: tuple[str, ...] = (
    # ARMv8 crypto (SHA/SM/AES base forms with `rr`/`rrr` variants)
    "SHA1H", "SHA1C", "SHA1M", "SHA1P", "SHA1SU0", "SHA1SU1",
    "SHA256H", "SHA256SU0", "SHA256SU1",
    "SHA512H", "SHA512SU0", "SHA512SU1",
    "SM3PARTW1", "SM3PARTW2", "SM3SS1", "SM3TT1A", "SM3TT1B",
    "SM3TT2A", "SM3TT2B", "SM4E", "SM4EKEY",
    "BCAX", "EOR3", "RAX1", "XAR",
    # SVE/SME ops whose variants encode dest/src purely in suffix
    # tokens that miss the per-element shape regex.
    "PFALSE", "RDFFR",
    "LD1RB", "LD1RH", "LD1RW", "LD1RD", "LD1RSB", "LD1RSH", "LD1RSW",
    "LD1ROB", "LD1ROH", "LD1ROW", "LD1ROD",
    "LD1RQB", "LD1RQH", "LD1RQW", "LD1RQD",
)


def _aarch64_variant_is_vec(internal: str) -> bool:
    return any(r.search(internal) for r in AARCH64_VEC_VARIANT_RES)

AARCH64_CROSS_LANE_PREFIXES: tuple[str, ...] = (
    "TBL", "TBX",
    "DUP", "EXT", "INS",
    "UMOV", "SMOV",
    "XTN", "ZIP", "UZP", "TRN", "REV",
    "ADDP", "FADDP", "SMAXP", "UMAXP", "SMINP", "UMINP",
    "FMAXP", "FMINP",
    "SADDLP", "UADDLP", "SADALP", "UADALP",
    "ADDV", "SMAXV", "UMAXV", "SMINV", "UMINV",
    "FMAXV", "FMINV",
    "SQXTN", "UQXTN",
)


def classify_aarch64_lane(const_name: str,
                          variants: tuple) -> tuple[str, bool] | None:
    name = const_name.removeprefix("AARCH64_INS_")
    by_variant = any(_aarch64_variant_is_vec(v.internal) for v in variants)
    by_name = any(name == p or name.startswith(p)
                  for p in AARCH64_VEC_NAME_PREFIXES)
    if not (by_variant or by_name):
        return None
    for p in AARCH64_CROSS_LANE_PREFIXES:
        if name.startswith(p):
            return ("LANE_MASK_KIND_STATIC", False)
    return ("LANE_MASK_KIND_STATIC", True)


# RISC-V V — every V*-prefixed Capstone canonical that isn't VSET*
# is a V-extension data-path instruction.  The variant.internal name
# is just "RISCV_<mnemonic>" with no extra operand-class tokens, so
# no variant-side gate is needed (and the previous gate misfired on
# spurious literal patterns at the RISCV_/canonical-name boundary).
RISCV_V_CROSS_LANE_PREFIXES: tuple[str, ...] = (
    # Permutations across lanes
    "VRGATHER", "VSLIDE", "VFSLIDE",
    "VCOMPRESS",
    # Integer reductions
    "VREDSUM", "VREDMAXU", "VREDMAX", "VREDMINU", "VREDMIN",
    "VREDAND", "VREDOR", "VREDXOR",
    "VWREDSUMU", "VWREDSUM",
    # FP reductions
    "VFREDOSUM", "VFREDUSUM", "VFREDMAX", "VFREDMIN",
    "VFWREDOSUM", "VFWREDUSUM",
    # Mask reductions (popcount / find-first)
    "VPOPC", "VCPOP", "VFIRST",
    # Mask scans / prefix-sum
    "VMSBF", "VMSIF", "VMSOF", "VIOTA",
    # Element <-> scalar bridges
    "VMV_X", "VMV_S",
    "VFMV_F", "VFMV_S",
)


def classify_riscv_lane(const_name: str,
                        variants: tuple) -> tuple[str, bool] | None:
    name = const_name.removeprefix("RISCV_INS_")
    # vset* are config insns, not vec data ops.
    if name.startswith("VSET"):
        return None
    if not name.startswith("V"):
        return None
    for p in RISCV_V_CROSS_LANE_PREFIXES:
        if name.startswith(p):
            return ("LANE_MASK_KIND_RISCV_VTYPE", False)
    return ("LANE_MASK_KIND_RISCV_VTYPE", True)


# MIPS MSA — canonical names end in _B / _H / _W / _D (per-lane
# element ops) or _V (whole-register bitwise ops).  Variant names
# stay "clean" (no microMIPS / nanoMIPS / DSP suffix).
#
# MSA FP variants legitimately start with F (FADD_W, FCEQ_W,
# FFINT_S_W, ...) — those are *not* scalar FPU.  Scalar FPU
# canonicals either lack the MSA lane suffix (ABS_S, NEG_D) or have
# variants tagged with format / micro-arch suffixes (_S, _D32, _D64,
# _MM*, _R6) that distinguish them from MSA.
MSA_LANE_SUFFIXES = ("_B", "_H", "_W", "_D", "_V")
MIPS_NON_MSA_VARIANT_SUFFIXES = ("_MM", "_MMR2", "_NM", "_R6", "_NMR6",
                                  "_D32", "_D64", "_D64_R6")
MIPS_MSA_CROSS_LANE_PREFIXES: tuple[str, ...] = (
    "SHF_", "PCKEV_", "PCKOD_", "ILVL_", "ILVR_", "ILVEV_", "ILVOD_",
    "VSHF_", "SPLATI_", "INSERT_", "INSVE_", "COPY_",
    "FEXDO_", "FEXUPL_", "FEXUPR_",
    "HADD_", "HSUB_",
)


def _mips_variant_is_msa(internal: str) -> bool:
    # MSA variants have clean names that don't carry the
    # microMIPS / nanoMIPS / DSP-format suffixes.  MSA FP ops do
    # start with F (FADD_W etc.) — only the scalar-FPU format
    # suffixes (_S/_D32/_D64/_MM*) distinguish non-MSA F* variants.
    stem = internal.removeprefix("MIPS_")
    for suf in MIPS_NON_MSA_VARIANT_SUFFIXES:
        if stem.endswith(suf):
            return False
    return True


def classify_mips_lane(const_name: str,
                       variants: tuple) -> tuple[str, bool] | None:
    name = const_name.removeprefix("MIPS_INS_")
    if not any(name.endswith(s) for s in MSA_LANE_SUFFIXES):
        return None
    # All variants must look MSA-clean.  DSP / FP-scalar / microMIPS
    # canonicals share the _B/_H/_W/_D suffixes but their variants
    # carry distinctive markers (_MM, _MMR2, _D32, _D64, _R6) that
    # knock them out.
    if not variants or not all(_mips_variant_is_msa(v.internal)
                                for v in variants):
        return None
    for p in MIPS_MSA_CROSS_LANE_PREFIXES:
        if name.startswith(p):
            return ("LANE_MASK_KIND_STATIC", False)
    return ("LANE_MASK_KIND_STATIC", True)


_LANE_CLASSIFIERS = {
    "x86":     classify_x86_lane,
    "aarch64": classify_aarch64_lane,
    "riscv":   classify_riscv_lane,
    "mips":    classify_mips_lane,
}


# Default lane-mask kind per ISA when an op is known-vector by its
# GEN_OP family but the Capstone-variant / name heuristics didn't
# recognise it (newer/extension SIMD: AVX-512 w/o width markers,
# 3DNow!/XOP, MIPS MSA/DSP, RISC-V CORE-V P-ext, ...).  RISC-V uses
# the vtype CSR; everyone else has a static per-instruction lane
# count.
_ISA_DEFAULT_LANE_KIND = {
    "riscv": "LANE_MASK_KIND_RISCV_VTYPE",
}

# Vector GEN_OP families whose dataflow is element-wise (lane k of
# the dst depends only on lane k of the srcs) — lane_parallel=True
# by default.  Everything else vector (shuffle/move/broadcast,
# loads/stores incl. gather/scatter, latency buckets) is treated
# cross-lane (False) when the heuristic couldn't decide: a wrong
# True wrongly licenses per-lane chain modelling, so the safe
# default is False.
_VEC_PARALLEL_FAMILIES = {
    "GEN_OP_VEC_ADD", "GEN_OP_VEC_SUB", "GEN_OP_VEC_MUL",
    "GEN_OP_VEC_DIV", "GEN_OP_VEC_SQRT", "GEN_OP_VEC_MADD",
    "GEN_OP_VEC_MSUB", "GEN_OP_VEC_LOGIC",
}


def classify_lane_info(info: IsaInfo,
                       const_name: str,
                       gen_op: str) -> tuple[str, bool]:
    """Decide the lane-mask kind + lane_parallel for @const_name.

    Primary signal is the per-ISA Capstone-variant/name classifier.
    But a lane-mask kind drives how decode.cc captures the per-lane
    masks, so it MUST be present on every vector/SIMD instruction —
    a vector op left at LANE_MASK_KIND_NONE silently disables
    per-lane capture for that instruction.  So when the heuristic
    can't recognise an op the opcode classifier already placed in a
    GEN_OP_VEC_* family, fall back to the ISA's default kind with a
    family-derived lane_parallel.  Returns (lane_mask_kind,
    lane_parallel).
    """
    fn = _LANE_CLASSIFIERS.get(info.key)
    result = None
    if fn is not None:
        variants = _variants_by_canonical(info.key).get(const_name, ())
        result = fn(const_name, variants)
    if result is not None:
        return result
    if gen_op.startswith("GEN_OP_VEC_"):
        kind = _ISA_DEFAULT_LANE_KIND.get(info.key,
                                          "LANE_MASK_KIND_STATIC")
        return (kind, gen_op in _VEC_PARALLEL_FAMILIES)
    return ("LANE_MASK_KIND_NONE", False)


def norm_flags(flags: str) -> str:
    flags = re.sub(r"\s+", "", flags)
    if flags == "0":
        return "MF_NONE"
    if flags == "MF_NONE|MF_NONE":
        return "MF_NONE"
    return " | ".join(part for part in flags.split("|") if part != "MF_NONE") or "MF_NONE"


def add_flag(flags: str, flag: str) -> str:
    flags = norm_flags(flags)
    if flags == "MF_NONE":
        return flag
    parts = flags.split(" | ")
    if flag not in parts:
        parts.append(flag)
    return " | ".join(parts)


def c_mnemonic(const_name: str, prefix: str) -> str:
    return const_name.removeprefix(prefix).lower()


def enum_constants(info: IsaInfo) -> list[str]:
    text = info.capstone_header.read_text()
    try:
        start = text.index(info.prefix + "INVALID")
        end = text.index(info.prefix + "ENDING", start)
    except ValueError as exc:
        raise SystemExit(f"could not find instruction enum in {info.capstone_header}") from exc
    enum_text = text[start:end]
    seen: set[str] = set()
    names: list[str] = []
    # INVALID stays out — generated_body prepends a {} placeholder
    # for it explicitly so the dense positional list lines up with
    # the enum starting at index 0 without trying to classify
    # the INVALID name.
    for match in re.finditer(r"\b" + re.escape(info.prefix) + r"[A-Z0-9_]+\b", enum_text):
        name = match.group(0)
        if name.endswith("INVALID") or name.endswith("ENDING") or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def enum_reg_constants(info: IsaInfo) -> list[str]:
    text = info.capstone_header.read_text()
    try:
        start = text.index(info.reg_prefix + "INVALID")
        end = text.index(info.reg_prefix + "ENDING", start)
    except ValueError as exc:
        raise SystemExit(f"could not find register enum in {info.capstone_header}") from exc
    enum_text = text[start:end]
    seen: set[str] = set()
    names: list[str] = []
    # The leading INVALID slot is filled with a {} placeholder in
    # generated_reg_body so the dense positional list aligns with the
    # enum starting at index 0.  The classifier path below would
    # recurse on the INVALID name (the riscv reg classifier doesn't
    # special-case it), so we keep it out of the constants list.
    for match in re.finditer(r"\b" + re.escape(info.reg_prefix) + r"[A-Z0-9_]+\b", enum_text):
        name = match.group(0)
        if name.endswith("INVALID") or name.endswith("ENDING") or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def parse_existing(info: IsaInfo) -> dict[str, Entry]:
    text = info.header.read_text()
    body = table_body(text, info)
    entries: dict[str, Entry] = {}
    for match in ENTRY_RE.finditer(body):
        entries[match.group("const")] = Entry(
            match.group("op"),
            match.group("branch"),
            norm_flags(match.group("flags")),
            match.group("refine"),
            match.group("dep_refine"),
        )
    return entries


def table_body(text: str, info: IsaInfo) -> str:
    pat = re.compile(
        r"\bstatic\s+const\s+InsnClassification\s+"
        + re.escape(info.table)
        + r"\s*\[\s*"
        + re.escape(info.array_size)
        + r"\s*\]\s*=\s*\{",
        re.DOTALL,
    )
    match = pat.search(text)
    if not match:
        raise SystemExit(f"could not find table {info.table} in {info.header}")
    start = match.end()
    depth = 1
    pos = start
    while pos < len(text):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start:pos]
        pos += 1
    raise SystemExit(f"unterminated table {info.table} in {info.header}")


def replace_table_body(text: str, info: IsaInfo, new_body: str) -> str:
    pat = re.compile(
        r"\bstatic\s+const\s+InsnClassification\s+"
        + re.escape(info.table)
        + r"\s*\[\s*"
        + re.escape(info.array_size)
        + r"\s*\]\s*=\s*\{",
        re.DOTALL,
    )
    match = pat.search(text)
    if not match:
        raise SystemExit(f"could not find table {info.table} in {info.header}")
    start = match.end()
    depth = 1
    pos = start
    while pos < len(text):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[:start] + "\n" + new_body + text[pos:]
        pos += 1
    raise SystemExit(f"unterminated table {info.table} in {info.header}")


def replace_reg_table_body(text: str, info: IsaInfo, new_body: str) -> str:
    pat = re.compile(
        r"\bstatic\s+const\s+RegClassification\s+"
        + re.escape(info.reg_table)
        + r"\s*\[\s*"
        + re.escape(info.reg_array_size)
        + r"\s*\]\s*=\s*\{",
        re.DOTALL,
    )
    match = pat.search(text)
    if not match:
        raise SystemExit(f"could not find table {info.reg_table} in {info.header}")
    start = match.end()
    depth = 1
    pos = start
    while pos < len(text):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[:start] + "\n" + new_body + text[pos:]
        pos += 1
    raise SystemExit(f"unterminated table {info.reg_table} in {info.header}")


def ent(op: str, branch: str = "BRANCH_NONE", flags: str = "MF_NONE") -> Entry:
    return Entry(op, branch, norm_flags(flags))


def reg_ent(primary: str, aliases: list[str] | tuple[str, ...] = ()) -> RegEntry:
    aliases_t = tuple(aliases)
    if aliases_t == (primary,):
        aliases_t = ()
    return RegEntry(primary, aliases_t)


def reg_none() -> RegEntry:
    return RegEntry("REG_NONE")


def numbered(prefix: str, idx: int) -> str:
    return f"{prefix}{idx}"


def first_number(name: str) -> int | None:
    match = re.search(r"\d+", name)
    return int(match.group(0)) if match else None


def all_numbered(name: str, letter: str) -> list[int]:
    return [int(m.group(1)) for m in re.finditer(rf"(?<![A-Z]){letter}(\d+)", name)]


def reg_names_from_tokens(name: str, family: str, out_prefix: str) -> list[str]:
    regs: list[str] = []
    for num in all_numbered(name, family):
        reg = numbered(out_prefix, num)
        if reg not in regs:
            regs.append(reg)
    return regs


def riscv_vector_aliases(name: str) -> list[str]:
    # V0M2/V0M4/V0M8 denote LMUL register groups starting at V0.
    match = re.fullmatch(r"V(\d+)", name)
    if match:
        return [numbered("REG_VEC", int(match.group(1)))]
    match = re.fullmatch(r"V(\d+)M([248])", name)
    if match:
        base = int(match.group(1))
        width = int(match.group(2))
        return [numbered("REG_VEC", base + i) for i in range(width) if base + i < 64]
    regs: list[str] = []
    for token in name.split("_"):
        part = riscv_vector_aliases(token)
        if part:
            for reg in part:
                if reg not in regs:
                    regs.append(reg)
            continue
        match = re.fullmatch(r"V(\d+)", token)
        if match:
            reg = numbered("REG_VEC", int(match.group(1)))
            if reg not in regs:
                regs.append(reg)
    return regs


def classify_x86_reg(name: str) -> RegEntry:
    gpr_aliases = {
        "A": 0, "B": 3, "C": 1, "D": 2,
        "SI": 4, "DI": 5,
        "BP": None, "SP": "REG_SP",
    }
    if name in {"EIZ", "RIZ"}:
        return reg_none()
    if name in {"IP", "EIP", "RIP"}:
        return reg_ent("REG_PC")
    if name == "EFLAGS":
        return RegEntry("REG_FLAGS", is_int_flags=True)
    # FPSW is the x87 STATUS WORD -- condition codes C0-C3, the
    # exception flags and the stack-top pointer.  That is an FP
    # control/status word, which is exactly what REG_FCSR names on
    # every other ISA; on REG_FLAGS it sat with EFLAGS, so an
    # `fnstsw` took a false edge from every integer compare.  It is
    # also NOT an integer-flags writer, so it never carried
    # .is_int_flags and the metaflags side-channel is unaffected.
    if name == "FPSW":
        return reg_ent("REG_FCSR")
    segs = {"CS": 0, "DS": 1, "ES": 2, "FS": 3, "GS": 4, "SS": 5}
    if name in segs:
        return reg_ent(numbered("REG_SEG", segs[name]))
    # CR0-CR15 are sixteen architecturally distinct registers with
    # unrelated roles: CR0 mode bits, CR2 the faulting linear address,
    # CR3 the page-table base, CR4 feature enables, CR8 the task
    # priority.  On one ID every `mov %cr3, %rax` took a false edge
    # from every CR0 write.
    if match := re.fullmatch(r"CR(\d+)", name):
        return reg_ent(numbered("REG_CTRL", int(match.group(1))))
    # DR0-DR3 are four independent breakpoint addresses, DR6 the status
    # word and DR7 the control word -- distinct registers, one ID each.
    # DR4/DR5 are NOT separate registers: with CR4.DE clear they ALIAS
    # DR6/DR7, and with it set they fault.  An alias folds (R8.2), so
    # they name REG_DEBUG6/REG_DEBUG7 and REG_DEBUG4/5 stay unused.
    if match := re.fullmatch(r"DR(\d+)", name):
        num = int(match.group(1))
        if num in (4, 5):
            num += 2
        return reg_ent(numbered("REG_DEBUG", num))
    if match := re.fullmatch(r"K(\d+)", name):
        return reg_ent(numbered("REG_PRED", int(match.group(1))))
    if match := re.fullmatch(r"BND(\d+)", name):
        return reg_ent(numbered("REG_BOUND", int(match.group(1))))
    if match := re.fullmatch(r"(?:FP|ST)(\d+)", name):
        return reg_ent(numbered("REG_FPR", int(match.group(1))))
    # MMX MM0-MM7 are not a register file of their own: they ARE the
    # x87 data registers, the 64-bit mantissa field of each.  Writing
    # MM0 destroys the x87 value in that slot and forces the tag word
    # valid, which is why Intel requires EMMS between MMX and x87 use.
    # A renaming regfile has to respect that edge, so MMX belongs on
    # the FP bank with ST0-ST7.  On REG_VEC<n> it instead shared an ID
    # with XMM<n> -- genuinely independent hardware -- and manufactured
    # an edge between MMX and SSE code that does not exist.
    # (ST(i) is TOP-relative and MM<n> absolute; they coincide at
    # TOP=0, which is the state MMX code runs in.  The bank is right
    # either way; the index is exact for the traffic that occurs.)
    if match := re.fullmatch(r"MM(\d+)", name):
        return reg_ent(numbered("REG_FPR", int(match.group(1))))
    if match := re.fullmatch(r"[XYZ]MM(\d+)", name):
        return reg_ent(numbered("REG_VEC", int(match.group(1))))
    if match := re.fullmatch(r"R(\d+)(?:[BDW])?", name):
        return reg_ent(numbered("REG_GPR", int(match.group(1)) - 2))
    for base, target in gpr_aliases.items():
        if re.fullmatch(rf"[ER]?{base}[XHL]?|{base}L", name):
            if target == "REG_SP":
                return reg_ent("REG_SP")
            if target is None:
                return reg_ent("REG_FP_REG")
            return reg_ent(numbered("REG_GPR", target))
    return reg_none()


def aarch64_gpr(num: int) -> str:
    """One generic ID per architectural GPR, whichever way it is spelled.

    Capstone names x29 and x30 as FP and LR in the 64-bit view and as W29
    and W30 in the 32-bit one.  They are one register each: `mov w30, w0`
    writes exactly what `ret` reads.  Classifying the two spellings apart
    put the write on REG_GPR30 and the read on REG_LR and left no
    dependency edge between them at all, which is the same severance as a
    dropped operand and harder to see.  The semantic IDs win over the
    numeric ones, because a consumer driving a return-address stack keys
    on REG_LR.
    """
    if num == 29:
        return "REG_FP_REG"
    if num == 30:
        return "REG_LR"
    return numbered("REG_GPR", num)


def classify_aarch64_reg(name: str) -> RegEntry:
    if name in {"X_LANE", "Y_LANE"}:
        return reg_none()
    if name in {"WZR", "XZR"}:
        return reg_ent("REG_ZERO")
    if name in {"SP", "WSP"}:
        return reg_ent("REG_SP")
    if name == "LR":
        return reg_ent("REG_LR")
    if name == "LR_XZR":
        return reg_ent("REG_LR", ["REG_LR", "REG_ZERO"])
    if name == "FP":
        return reg_ent("REG_FP_REG")
    if name == "NZCV":
        return RegEntry("REG_FLAGS", is_int_flags=True)
    if name == "FPCR":
        return reg_ent("REG_FCSR")
    # VG is the vector-granule count -- the current SVE vector length,
    # which SMSTART/SMSTOP change.  That is vector CONFIGURATION, the
    # role REG_VCTRL carries for RISC-V vl/vtype, so it keeps the ID.
    if name == "VG":
        return reg_ent("REG_VCTRL")
    # FFR is the SVE First Fault Register: a separate architectural
    # register that first-faulting loads write and RDFFR/WRFFR move to
    # and from a P register.  Sharing REG_VCTRL with VG meant every
    # `rdffr` took an edge from every SMSTART.  It is predicate-shaped
    # and predicate-addressed, so it belongs in the predicate bank --
    # AArch64's architectural predicate file has sixteen entries
    # (P0-P15), leaving REG_PRED16 free for the one predicate that
    # sits outside the numbered file.
    if name == "FFR":
        return reg_ent("REG_PRED16")
    # The ZA tile names -- ZAB0, ZAH0-1, ZAS0-3, ZAD0-7, ZAQ0-15 -- are
    # OVERLAPPING VIEWS of one architectural array, not 31 registers: a
    # write through ZAS0 and a read through ZAD0 touch the same bytes.
    # Aliases fold (R8.2), so they and the whole-array ZA / Z_MATRIX
    # spellings stay on REG_MATRIX.  ZT0 is NOT one of them: it is the
    # SME2 lookup-table register, 512 bits of separate architectural
    # state that LUTI2/LUTI4 read and MOVT writes, and it needs its own
    # identity.  It goes in the vector bank's free upper half rather
    # than taking a new special ID -- REG_VEC32 is the first slot past
    # the 32 registers any traced ISA numbers.
    if name.startswith("ZT"):
        return reg_ent("REG_VEC32")
    if name.startswith("ZA") or name == "Z_MATRIX":
        return reg_ent("REG_MATRIX")
    if re.fullmatch(r"P\d+", name):
        return reg_ent(numbered("REG_PRED", int(name[1:])))
    # PN<n> is the predicate-as-counter VIEW of predicate register P<n>
    # (SVE2.1 / SME2), not a seventeenth-to-thirty-second predicate
    # register: AArch64 has one 16-entry predicate file and these
    # instructions reinterpret its contents.  Giving the two views
    # separate IDs meant a `ptrue p8.b` and the `pext ..., pn8[0]` that
    # consumes it recorded no edge.  disas/capstone.c and isaxcheck's
    # normaliser both already state the aliasing; this is the table
    # agreeing with them.
    if re.fullmatch(r"PN\d+", name):
        return reg_ent(numbered("REG_PRED", int(name[2:])))
    if name.startswith("P") and "_" in name:
        regs = reg_names_from_tokens(name, "P", "REG_PRED")
        return reg_ent(regs[0], regs) if regs else reg_none()
    if re.fullmatch(r"[BHSQDZ]\d+", name):
        return reg_ent(numbered("REG_VEC", first_number(name) or 0))
    if name[0] in "DQZ" and "_" in name:
        regs = reg_names_from_tokens(name, name[0], "REG_VEC")
        return reg_ent(regs[0], regs) if regs else reg_none()
    if re.fullmatch(r"W\d+", name) or re.fullmatch(r"X\d+", name):
        return reg_ent(aarch64_gpr(first_number(name) or 0))
    if name.startswith(("W", "X")) and "_" in name:
        regs: list[str] = []
        for token in name.split("_"):
            if token == "FP":
                reg = "REG_FP_REG"
            elif token in {"LR", "XZR", "WZR"}:
                reg = "REG_LR" if token == "LR" else "REG_ZERO"
            elif re.fullmatch(r"[WX]\d+", token):
                reg = aarch64_gpr(first_number(token) or 0)
            else:
                reg = None
            if reg and reg not in regs:
                regs.append(reg)
        return reg_ent(regs[0], regs) if regs else reg_none()
    return reg_none()


def classify_riscv_reg(name: str) -> RegEntry:
    if name in {"X0", "X0_PAIR", "DUMMY_REG_PAIR_WITH_X0"}:
        return reg_ent("REG_ZERO")
    # ssp is the Zicfiss shadow-stack pointer.  It is NOT the data stack
    # pointer and it is NOT the link register: the shadow stack is a
    # separate architectural structure with its own pointer, so folding
    # it onto either one manufactures a dependency the guest does not
    # have -- against every spill and frame adjustment on REG_SP, or
    # against every call and return on REG_LR.  x86-64 CET carries the
    # same register, so REG_SSP is not a single-ISA ID.
    if name == "SSP":
        return reg_ent("REG_SSP")
    if name in {"FFLAGS", "FRM"}:
        return reg_ent("REG_FCSR")
    # vl and vtype are the vector CONFIGURATION a vsetvl writes as a
    # pair and every vector instruction reads.
    if name in {"VL", "VTYPE"}:
        return reg_ent("REG_VCTRL")
    # vxrm and vxsat are fields of vcsr -- the fixed-point rounding mode
    # and the saturation flag.  A rounding-mode-and-status word is what
    # REG_FCSR already is, and `vcsr` is `fcsr`'s sibling CSR, so they
    # fold there rather than onto the vector CONFIGURATION ID.  The
    # generic space does not mint an ID per architectural quirk.
    if name in {"VXRM", "VXSAT"}:
        return reg_ent("REG_FCSR")
    # vlenb is VLEN in bytes: a read-only implementation constant, in
    # the same class as the ID registers, and never written by anything.
    # On REG_VCTRL a read of it would take a false edge from the last
    # vsetvli, which does not change VLEN.  REG_SYSID is that class made
    # explicit, shared with MIPS PRId/Config and fcr0.
    if name == "VLENB":
        return reg_ent("REG_SYSID")
    if re.fullmatch(r"X\d+", name):
        num = first_number(name) or 0
        if num == 1:
            return reg_ent("REG_LR")
        if num == 2:
            return reg_ent("REG_SP")
        if num == 8:
            return reg_ent("REG_FP_REG")
        return reg_ent(numbered("REG_GPR", num))
    if name.startswith("X") and "_" in name:
        regs: list[str] = []
        for num in all_numbered(name, "X"):
            reg = "REG_ZERO" if num == 0 else "REG_LR" if num == 1 else "REG_SP" if num == 2 else "REG_FP_REG" if num == 8 else numbered("REG_GPR", num)
            if reg not in regs:
                regs.append(reg)
        return reg_ent(regs[0], regs) if regs else reg_none()
    if match := re.fullmatch(r"F(\d+)_[DFH]", name):
        return reg_ent(numbered("REG_FPR", int(match.group(1))))
    regs = riscv_vector_aliases(name)
    if regs:
        return reg_ent(regs[0], regs)
    return reg_none()


MIPS_GPR_NUM = {
    "AT": 1, "V0": 2, "V1": 3,
    "A0": 4, "A1": 5, "A2": 6, "A3": 7,
    "A4": 8, "A5": 9, "A6": 10, "A7": 11,
    "T0": 8, "T1": 9, "T2": 10, "T3": 11, "T4": 12, "T5": 13,
    "T6": 14, "T7": 15, "S0": 16, "S1": 17, "S2": 18, "S3": 19,
    "S4": 20, "S5": 21, "S6": 22, "S7": 23, "T8": 24, "T9": 25,
    "K0": 26, "K1": 27, "GP": 28, "SP": 29, "FP": 30, "RA": 31,
}


# ---------------------------------------------------------------------
# MIPS privileged state, grouped by DEPENDENCE BEHAVIOUR
#
# Every CP0 register used to land on REG_SYS -- 288 entries on one ID.
# That is not a fold onto a shared behaviour, it is a conflation: a
# consumer saw `mfc0 $t0, $Config3` ordered behind `mtc0 $t0, $Status`,
# and it had no way to tell that edge from a real one.  It also blocked
# recording the CP0 state an exception writes, because attributing
# EPC/Cause/Status to a trapping instruction would have made EVERY
# trapping instruction depend on EVERY unrelated CP0 access.
#
# 288 IDs is not the answer either.  The groups below are the sets whose
# members a consumer must order against the SAME event, so an edge
# inside a group is real and an edge across groups is not:
#
#   REG_SYSEXC    written together BY an exception and read by its
#                 handler.  One event writes EPC, Cause, Status and
#                 BadVAddr, so ordering a handler's reads of them
#                 against each other costs nothing false.
#   REG_SYSMMU    read and written by TLB maintenance (tlbr/tlbwi/
#                 tlbwr/tlbp) and by the hardware page-table walker.
#   REG_SYSTIMER  a counter that advances on its own and the compare
#                 value that fires against it.  A read of Count depends
#                 on nothing in the instruction stream.
#   REG_SYSPERF   counters that advance on hardware events, likewise.
#   REG_SYSDBG    EJTAG debug, watchpoints and trace.
#   REG_SYSCACHE  cache tag/data access windows and error state.
#   REG_SYSID     read-only implementation identification and
#                 configuration.  A read of one of these can never
#                 depend on anything, so it must not share an ID with
#                 writable state -- the same reason RISC-V vlenb does
#                 not sit on the vector-configuration ID.
#   REG_SYS       the residual: scratch, permission and MT/virtualisation
#                 control.
#
# WHAT A TRACE ACTUALLY CARRIES.  Capstone models CP0 twice: by NUMBER
# (MIPS_REG_COP0<n>, printed "$12") and by NAME (MIPS_REG_COP0SEL_
# STATUS).  A 537M-encoding sweep in the modes the tracer opens
# (mips32r2le, 82.9M decodes) reached all 32 numeric constants and NONE
# of the 161 named ones, so the numeric rows are what a real decode
# produces and the named rows are mapped for completeness.  A register
# NUMBER cannot see the select field, so where one number carries
# selects of different roles its row takes the role that dominates its
# traffic; that is named at the row, and it is why the two spellings can
# disagree for register 15 (PRId, read constantly, versus EBase, written
# once at boot).
MIPS_CP0_NUM_GROUP = {
    0:  "REG_SYSMMU",    # Index
    1:  "REG_SYSMMU",    # Random
    2:  "REG_SYSMMU",    # EntryLo0
    3:  "REG_SYSMMU",    # EntryLo1
    4:  "REG_SYSMMU",    # Context / ContextConfig  (sel 2 is UserLocal:
                         # the thread pointer, reachable as HWR29 and
                         # mapped to REG_TLS there)
    5:  "REG_SYSMMU",    # PageMask / PageGrain / SegCtl / PWBase-Size
    6:  "REG_SYSMMU",    # Wired / PWCtl
    7:  "REG_SYS",       # HWREna -- a permission mask, not TLB state
    8:  "REG_SYSEXC",    # BadVAddr / BadInstr / BadInstrP / BadInstrX
    9:  "REG_SYSTIMER",  # Count
    10: "REG_SYSMMU",    # EntryHi
    11: "REG_SYSTIMER",  # Compare
    12: "REG_SYSEXC",    # Status / IntCtl / SRSCtl / SRSMap
    13: "REG_SYSEXC",    # Cause
    14: "REG_SYSEXC",    # EPC / NestedEPC
    15: "REG_SYSID",     # PRId (+EBase, CDMMBase, CMGCRBase, BEVVA --
                         # PRId dominates the traffic and is read-only;
                         # EBase is written once at boot)
    16: "REG_SYSID",     # Config / Config1-5
    17: "REG_SYS",       # LLAddr
    18: "REG_SYSDBG",    # WatchLo0-15
    19: "REG_SYSDBG",    # WatchHi0-15
    20: "REG_SYSMMU",    # XContext / XContextConfig
    21: "REG_SYS",       # reserved
    22: "REG_SYS",       # implementation-dependent
    23: "REG_SYSDBG",    # Debug / Debug2 / TraceControl / TraceIBPC
    24: "REG_SYSDBG",    # DEPC / TraceControl3 / UserTraceData2
    25: "REG_SYSPERF",   # PerfCtl0-7 / PerfCnt0-7
    26: "REG_SYSCACHE",  # ErrCtl
    27: "REG_SYSCACHE",  # CacheErr
    28: "REG_SYSCACHE",  # ITagLo / IDataLo / DTagLo / DDataLo
    29: "REG_SYSCACHE",  # ITagHi / IDataHi / DTagHi / DDataHi
    30: "REG_SYSEXC",    # ErrorEPC
    31: "REG_SYS",       # DESAVE + KScratch1-6 (two unrelated uses, so
                         # neither group claims the number)
}

# Named CP0 constants, classified by ROLE.  Exact-prefix families first,
# then whole names; anything unlisted falls to REG_SYS.
MIPS_CP0_NAME_PREFIX_GROUP = (
    ("WATCHLO",   "REG_SYSDBG"),
    ("WATCHHI",   "REG_SYSDBG"),
    ("TRACE",     "REG_SYSDBG"),
    ("USERTRACEDATA", "REG_SYSDBG"),
    ("DEBUG",     "REG_SYSDBG"),
    ("PERFCNT",   "REG_SYSPERF"),
    ("PERFCTL",   "REG_SYSPERF"),
    ("CONFIG",    "REG_SYSID"),
    ("SRSCONF",   "REG_SYSID"),
    ("MVPCONF",   "REG_SYSID"),
    ("SEGCTL",    "REG_SYSMMU"),
    ("ENTRYLO",   "REG_SYSMMU"),
)
MIPS_CP0_NAME_GROUP = {
    # exception state
    "STATUS": "REG_SYSEXC", "CAUSE": "REG_SYSEXC", "EPC": "REG_SYSEXC",
    "ERROREPC": "REG_SYSEXC", "BADVADDR": "REG_SYSEXC",
    "BADINST": "REG_SYSEXC", "BADINSTRP": "REG_SYSEXC",
    "BADINSTRX": "REG_SYSEXC", "NESTEDEPC": "REG_SYSEXC",
    "NESTEDEXC": "REG_SYSEXC", "SRSCTL": "REG_SYSEXC",
    "SRSMAP": "REG_SYSEXC", "SRSMAP2": "REG_SYSEXC",
    "INTCTL": "REG_SYSEXC", "VIEW_IPL": "REG_SYSEXC",
    "VIEW_RIPL": "REG_SYSEXC", "EBASE": "REG_SYSEXC",
    "BEVVA": "REG_SYSEXC",
    # address translation
    "INDEX": "REG_SYSMMU", "RANDOM": "REG_SYSMMU",
    "CONTEXT": "REG_SYSMMU", "CONTEXTCONFIG": "REG_SYSMMU",
    "XCONTEXT": "REG_SYSMMU", "XCONTEXTCONFIG": "REG_SYSMMU",
    "PAGEMASK": "REG_SYSMMU", "PAGEGRAIN": "REG_SYSMMU",
    "WIRED": "REG_SYSMMU", "ENTRYHI": "REG_SYSMMU",
    "PWBASE": "REG_SYSMMU", "PWFIELD": "REG_SYSMMU",
    "PWSIZE": "REG_SYSMMU", "PWCTL": "REG_SYSMMU",
    "MAAR": "REG_SYSMMU", "MAARI": "REG_SYSMMU",
    "MEMORYMAPID": "REG_SYSMMU",
    # counters
    "COUNT": "REG_SYSTIMER", "COMPARE": "REG_SYSTIMER",
    # cache windows and error state
    "ERRCTL": "REG_SYSCACHE", "CACHEERR": "REG_SYSCACHE",
    "ITAGLO": "REG_SYSCACHE", "IDATALO": "REG_SYSCACHE",
    "DTAGLO": "REG_SYSCACHE", "DDATALO": "REG_SYSCACHE",
    "ITAGHI": "REG_SYSCACHE", "IDATAHI": "REG_SYSCACHE",
    "DTAGHI": "REG_SYSCACHE", "DDATAHI": "REG_SYSCACHE",
    # read-only identification
    "PRID": "REG_SYSID", "CDMMBASE": "REG_SYSID",
    "CMGCRBASE": "REG_SYSID", "GLOBALNUMBER": "REG_SYSID",
    # UserLocal IS the thread pointer -- the same register `rdhwr $29`
    # reads, which already maps to REG_TLS.  The two spellings of one
    # register agree.
    "USERLOCAL": "REG_TLS",
}


def mips_cp0_group(sel_name: str) -> str:
    """Generic ID for a named MIPS CP0 register (COP0SEL_<name>)."""
    if sel_name in MIPS_CP0_NAME_GROUP:
        return MIPS_CP0_NAME_GROUP[sel_name]
    for prefix, group in MIPS_CP0_NAME_PREFIX_GROUP:
        if sel_name.startswith(prefix):
            return group
    return "REG_SYS"


def classify_mips_reg(name: str) -> RegEntry:
    stem = re.sub(r"(?:_NM|_64)$", "", name)
    if stem == "ZERO":
        return reg_ent("REG_ZERO")
    if stem == "PC":
        return reg_ent("REG_PC")
    if stem == "SP":
        return reg_ent("REG_SP")
    if stem == "FP":
        return reg_ent("REG_FP_REG")
    if stem == "RA":
        return reg_ent("REG_LR")
    if stem in MIPS_GPR_NUM:
        return reg_ent(numbered("REG_GPR", MIPS_GPR_NUM[stem]))
    if match := re.fullmatch(r"F(\d+)", stem):
        return reg_ent(numbered("REG_FPR", int(match.group(1))))
    # The double-precision VIEW of the FP register file, and which
    # register `D<n>` denotes depends on FR.  Under FR=1 -- the `_64`
    # rows -- a double is $f<n>, one for one.  Under FR=0 it is the
    # even-odd PAIR starting at $f<2n>, which is why Capstone prints
    # D<n> as "f<2n>".  Mapping the FR=0 row to REG_FPR<n> gave one
    # architectural register two generic IDs: `D1` (printed f2) landed
    # on REG_FPR1 while `F2` (printed f2) landed on REG_FPR2.  Latent
    # rather than live -- Capstone returns F<n> ids in the mode the
    # tracer opens, so a real `add.d` decode never consults these rows
    # -- but a table that disagrees with itself is a defect waiting for
    # the mode to change.
    #
    # The pair's odd half is deliberately NOT named here.  In FR=0 an
    # `add.d $f2, ...` reads f3 as well, and the LIVE path models that
    # the same way this does: `F2` maps to REG_FPR2 alone.  Naming the
    # second half on the dead row only would make the two paths
    # disagree about the same architectural fact; if the pair is ever
    # modelled it belongs on both.
    if match := re.fullmatch(r"D(\d+)", stem):
        num = int(match.group(1))
        return reg_ent(numbered("REG_FPR", num if name.endswith("_64")
                                else 2 * num))
    if match := re.fullmatch(r"F_HI(\d+)", stem):
        return reg_ent(numbered("REG_FPR", int(match.group(1))))
    if match := re.fullmatch(r"W(\d+)", stem):
        return reg_ent(numbered("REG_VEC", int(match.group(1))))
    # FCC0-7 are the FP condition-code bits -- genuine predicate
    # registers.  MSA<n> used to come through here too, which put the
    # RESERVED MSA CONTROL registers 8-31 on REG_PRED8..31: the wrong
    # register class entirely.  They are handled with the rest of the
    # MSA control file below.
    if match := re.fullmatch(r"FCC(\d+)", stem):
        return reg_ent(numbered("REG_PRED", int(match.group(1)) % 32))
    # HI and LO are architecturally DISTINCT.  `mfhi` and `mflo` read
    # different hardware, binutils mips-opc.c separates them, and QEMU
    # exposes them as two GDB registers (gdb-xml/mips-cpu.xml "hi" and
    # "lo").  One generic ID for both was a conflation no consumer
    # could undo: it saw one register where the machine has two.  The
    # LOW half keeps REG_ACC<n>; the HIGH half takes REG_ACCHI<n>.
    #
    # AC<n> is the MIPS DSP name for the WHOLE 64-bit accumulator, so
    # it maps to both halves as a register LIST -- the same shape as
    # the AArch64 D0_D1 forms, not a fold.  Capstone reports `mfhi`
    # and `mflo` as reading AC<n> as well, which is a Capstone defect
    # (measured: both yield MIPS_REG_AC0, while `mult` correctly
    # writes MIPS_REG_HI0 and MIPS_REG_LO0 separately).  It is
    # repaired at the decode boundary in refine_alias_fields, not
    # here: this table is keyed by REGISTER and the discriminator is
    # the INSTRUCTION.
    if match := re.fullmatch(r"HI(\d+)", stem):
        return reg_ent(numbered("REG_ACCHI", int(match.group(1)) % 4))
    if match := re.fullmatch(r"LO(\d+)", stem):
        return reg_ent(numbered("REG_ACC", int(match.group(1)) % 4))
    if match := re.fullmatch(r"AC(\d+)", stem):
        num = int(match.group(1)) % 4
        return reg_ent(numbered("REG_ACC", num),
                       [numbered("REG_ACC", num),
                        numbered("REG_ACCHI", num)])
    # MPL<n> and P<n> are LLVM's DSP multiplier-pipeline scheduling
    # pseudo-registers; the MIPS architecture defines no such
    # registers.  A 537M-encoding sweep of the SPECIAL / COP0-3 /
    # SPECIAL2 / MSA / SPECIAL3 spaces (82.9M decodes, mips32r2le)
    # produced AC0-3, HI0-3 and LO0-3 and none of these -- which is
    # what a pseudo-register looks like from outside a compiler.  On
    # REG_ACC<n> they sat on top of the real LOW half.  They are not
    # registers, so they name none.
    if re.fullmatch(r"(?:MPL|P)\d+", stem):
        return reg_none()
    # FP control file.  fcr0 (FIR) is the read-only implementation
    # register -- the same class as MIPS PRId and RISC-V vlenb -- so it
    # takes REG_SYSID: a read of it can never depend on anything and
    # must not share an ID with the writable status word.  fcr31 IS the
    # FCSR; fcr25/26/28 (FCCR / FEXR / FENR) are alternate VIEWS of the
    # same fcr31 state and fold there as aliases.  Every other FCR
    # encoding is architecturally RESERVED -- not distinct hardware, so
    # naming it alongside FCSR is not an overlap.
    if stem == "FCR0":
        return reg_ent("REG_SYSID")
    if stem.startswith("FCR"):
        return reg_ent("REG_FCSR")
    # Hardware register 29 is CP0 UserLocal, the MIPS thread pointer, and
    # the only CP0 word user code reads directly (through rdhwr).  On
    # REG_SYS every TLS access would share a slot with the entire CP0
    # population, so it gets the same REG_TLS the AArch64 TPIDR_EL0 does.
    if stem == "HWR29":
        return reg_ent("REG_TLS")
    # HWR2 is CC, a free-running cycle counter; HWR0/1/3 (CPUNum,
    # SYNCI_Step, CCRes) are read-only implementation constants.  Only
    # HWR29 is reachable -- the encoding sweep produced no other HWR
    # constant -- so these rows are correctness for a decode we have not
    # seen rather than traffic the wire carries.
    if stem == "HWR2":
        return reg_ent("REG_SYSTIMER")
    if stem in {"HWR0", "HWR1", "HWR3"}:
        return reg_ent("REG_SYSID")
    if stem.startswith("HWR"):
        return reg_ent("REG_SYS")
    # CP0 -- the system coprocessor -- split by dependence behaviour.
    # The numeric spelling is what a real decode produces (all 32
    # reached in the sweep); the named spelling reached none of 161 and
    # is mapped for completeness.
    if match := re.fullmatch(r"COP0(\d+)", stem):
        return reg_ent(MIPS_CP0_NUM_GROUP[int(match.group(1)) % 32])
    if stem.startswith("COP0SEL_"):
        return reg_ent(mips_cp0_group(stem[len("COP0SEL_"):]))
    # CP2 and CP3 are implementation-defined coprocessors: the
    # architecture assigns their registers no semantics, so there is
    # nothing to group BY.  One ID per coprocessor file, which is what
    # keeps them out of the CP0 classes -- the defect that mattered.
    # CP2 is reachable (mfc2/ctc2 decode, all 32 constants); CP3 is not.
    if re.fullmatch(r"COP2\d+", stem):
        return reg_ent("REG_COPROC0")
    if re.fullmatch(r"COP3\d+", stem):
        return reg_ent("REG_COPROC1")
    if stem.startswith("COP"):
        return reg_ent("REG_SYS")
    # DSPControl's fields are condition, carry, outflag, pos, scount and
    # EFI -- a flags word, which is what REG_FLAGS is.  It exists on
    # MIPS alone, so it gets no ID of its own: a single-ISA register
    # folds onto whichever existing ID roughly matches its role.
    if stem.startswith("DSP"):
        return reg_ent("REG_FLAGS")
    # MSA control file.  MSACSR is the vector unit's rounding mode and
    # exception flags -- the role REG_FCSR already carries for the
    # scalar FP unit, and not REG_VCTRL, which carries vector
    # CONFIGURATION.  MSAIR is the read-only implementation register and
    # joins the identification class.  The other six named ones
    # (MSAAccess / Save / Modify / Request / Map / Unmap, control
    # registers 2-7) are implementation-dependent context-management
    # registers: one function, so one ID, which is a group and not a
    # conflation.  MSA8..MSA31 are the RESERVED control-register
    # encodings and land here too; they used to reach REG_PRED8..31.
    if stem == "MSAIR":
        return reg_ent("REG_SYSID")
    if stem == "MSACSR":
        return reg_ent("REG_FCSR")
    if stem.startswith("MSA"):
        return reg_ent("REG_SYS")
    return reg_none()


REG_CLASSIFIERS = {
    "x86": classify_x86_reg,
    "aarch64": classify_aarch64_reg,
    "riscv": classify_riscv_reg,
    "mips": classify_mips_reg,
}


def classify_reg(info: IsaInfo, const_name: str) -> RegEntry:
    return REG_CLASSIFIERS[info.key](const_name.removeprefix(info.reg_prefix))


MADD_OPS = {
    "GEN_OP_INT_MADD", "GEN_OP_INT_MSUB",
    "GEN_OP_FP_MADD", "GEN_OP_FP_MSUB",
    "GEN_OP_VEC_MADD", "GEN_OP_VEC_MSUB",
}

# Scalar-FP opcodes with a faithful packed-vector twin.  Rows the
# classifier puts here get .refine = refine_arm64_fp_vec (AArch64),
# which promotes FP_* -> VEC_* at decode when the operands show a
# real vector arrangement.  FP_CMP / FP_CVT are intentionally absent:
# the enum has no VEC_CMP / VEC_CVT and the project keeps vector
# FCMEQ / FCVTZS as FP_CMP / FP_CVT by convention.
FP_VEC_PROMOTE_OPS = {
    "GEN_OP_FP_ADD":  "GEN_OP_VEC_ADD",
    "GEN_OP_FP_SUB":  "GEN_OP_VEC_SUB",
    "GEN_OP_FP_MUL":  "GEN_OP_VEC_MUL",
    "GEN_OP_FP_DIV":  "GEN_OP_VEC_DIV",
    "GEN_OP_FP_SQRT": "GEN_OP_VEC_SQRT",
    "GEN_OP_FP_MADD": "GEN_OP_VEC_MADD",
    "GEN_OP_FP_MSUB": "GEN_OP_VEC_MSUB",
    "GEN_OP_FP_MOV":  "GEN_OP_VEC_MOV",
}


# AArch64 flag-writing arithmetic mnemonics whose XZR-dst form is
# the assembler alias for CMP / CMN / TST.  Rows on this list get
# .refine = refine_arm64_cmp_alias, which detects the flag-only
# shape at decode and promotes the opcode.  Other flag-writing
# variants (ADCS, SBCS, BICS, ...) don't have CMP-style aliases in
# the AArch64 assembler grammar, so they stay on their canonical
# arithmetic opcode even when written with an XZR destination.
CMP_ALIAS_PROMOTE_INSNS = {
    "AARCH64_INS_SUBS",
    "AARCH64_INS_ADDS",
    "AARCH64_INS_ANDS",
}


# Per-ISA mnemonics that the access-pattern classifier mis-classifies
# as dep_all_to_all because Capstone's source-table operand list is
# either uniformly under-tagged (single CS_AC_WRITE or CS_AC_READ
# entry, no MEM operand recorded) or has a writeback variant whose
# (W, W, R) shape doesn't fit passthrough's single-output rule.  At
# runtime, QEMU's plugin operand walker reads the actual operand
# list from per-execution detail — the simple non-writeback shape
# is the regular passthrough rm-form (load) or mr-form (store),
# both of which dep_passthrough's internal dispatch handles
# precisely.  Writeback variants get the multi-dst shape that the
# refiner's defensive bail-out path leaves on dep_all_to_all, so
# binding the canonical to dep_passthrough is strictly an
# improvement: no regression on writeback, real precision win on
# the simple forms used by 99% of real code and exact-check probes.
ISA_DEP_PASSTHROUGH_LOAD_INSNS: dict[str, set[str]] = {
    "aarch64": {
        "AARCH64_INS_LDR",
        "AARCH64_INS_LDRB",  "AARCH64_INS_LDRH",
        "AARCH64_INS_LDRSB", "AARCH64_INS_LDRSH", "AARCH64_INS_LDRSW",
        "AARCH64_INS_LDUR",
        "AARCH64_INS_LDURB", "AARCH64_INS_LDURH",
        "AARCH64_INS_LDURSB","AARCH64_INS_LDURSH","AARCH64_INS_LDURSW",
        "AARCH64_INS_LDAR",  "AARCH64_INS_LDAXR",
        "AARCH64_INS_LDXR",
    },
    "riscv": {
        "RISCV_INS_LB", "RISCV_INS_LH", "RISCV_INS_LW", "RISCV_INS_LD",
        "RISCV_INS_LBU", "RISCV_INS_LHU", "RISCV_INS_LWU",
        "RISCV_INS_FLW", "RISCV_INS_FLD",
        "RISCV_INS_FLH",
    },
    "mips": {
        "MIPS_INS_LB",  "MIPS_INS_LBU",
        "MIPS_INS_LH",  "MIPS_INS_LHU",
        "MIPS_INS_LW",  "MIPS_INS_LWU",
        "MIPS_INS_LD",
        "MIPS_INS_LWC1", "MIPS_INS_LDC1",
    },
}
ISA_DEP_PASSTHROUGH_STORE_INSNS: dict[str, set[str]] = {
    "aarch64": {
        "AARCH64_INS_STR",
        "AARCH64_INS_STRB", "AARCH64_INS_STRH",
        "AARCH64_INS_STUR",
        "AARCH64_INS_STURB", "AARCH64_INS_STURH",
        "AARCH64_INS_STLR", "AARCH64_INS_STLXR",
        "AARCH64_INS_STXR",
    },
    "riscv": {
        "RISCV_INS_SB", "RISCV_INS_SH", "RISCV_INS_SW", "RISCV_INS_SD",
        "RISCV_INS_FSW", "RISCV_INS_FSD", "RISCV_INS_FSH",
    },
    "mips": {
        "MIPS_INS_SB",  "MIPS_INS_SH",  "MIPS_INS_SW",  "MIPS_INS_SD",
        "MIPS_INS_SWC1", "MIPS_INS_SDC1",
    },
}


def classify_x86(m: str) -> Entry:
    jcc = {
        "ja", "jae", "jb", "jbe", "jc", "je", "jecxz", "jg", "jge",
        "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne",
        "jng", "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz",
        "jo", "jp", "jpe", "jpo", "jrcxz", "js", "jz", "jcxz",
        "loop", "loope", "loopne",
    }
    if m in jcc:
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    if m in {"jmp", "ljmp"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"call", "lcall"}:
        # X86_INS_CALL covers both direct (immediate target) and indirect
        # (register/memory target); the decoder refines DIRECT_CALL ->
        # INDIRECT_CALL from the operand at run time.
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_CALL")
    if m.startswith("ret") or m.startswith("iret"):
        return ent("GEN_OP_RET", "BRANCH_RETURN")
    # Trap taxonomy (see the identical rules in the other classify_* below).
    # Three behaviours hide under "trap", and only the first two redirect fetch:
    #   syscall           -- a deliberate call into the kernel; always transfers.
    #   unconditional trap -- always raises (ud2, int3, brk, ebreak, break).
    #                        Fetch diverts to a vector every time, so it ends a
    #                        block exactly as a syscall does.
    #   CONDITIONAL trap   -- raises only when its condition holds, and carries
    #                        no target field: nothing to fetch, no prediction to
    #                        make, so the front end simply runs on to the next
    #                        instruction.  It is a compare that may except, and
    #                        is classified as one -- the same GEN_OP_CMP /
    #                        BRANCH_NONE that BOUND has always had.  Typing it
    #                        as an unconditional transfer instead seals a block
    #                        at an edge nothing can walk, which is how MIPS's
    #                        divide-by-zero guards became degenerate one-
    #                        instruction blocks with no wrong path at all.  When
    #                        one does fire, it is an exception, and the fault
    #                        machinery models it as such.
    if m in {"syscall", "sysenter", "sysexit", "int", "int1", "int3", "vmcall", "vmmcall",
             "ud0", "ud1", "ud2"}:
        return ent("GEN_OP_SYSCALL", "BRANCH_SYSCALL_TYPE")
    if m in {"hlt", "cpuid", "rdtsc", "rdtscp", "xgetbv", "xsetbv", "endbr32", "endbr64", "wait", "clc", "cld", "cli", "sti", "clac", "stac", "clts", "cmc", "stc", "std", "pause", "clgi", "getsec", "pconfig", "rsm", "skinit", "stgi", "swapgs", "encls", "enclu", "enclv", "emms", "data16", "lock", "rep", "repne", "rex64", "xacquire", "xrelease"}:
        return ent("GEN_OP_NOP")
    if m.startswith("prefetch"):
        return ent("GEN_OP_PREFETCH")
    if m.startswith("nop"):
        return ent("GEN_OP_NOP")
    if m.startswith(("lfence", "mfence", "sfence")):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")

    if re.match(r"^(lzcnt|tzcnt|popcnt)", m):
        return ent("GEN_OP_BITMANIP")
    if m in {"aaa", "aad", "aam", "aas", "daa", "das"}:
        return ent("GEN_OP_INT_ADD")
    if m.startswith("adox"):
        return ent("GEN_OP_INT_ADD")
    if m.startswith(("aes", "sha", "xcrypt", "xsha")):
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith(("gf2p8mul", "pclmul")):
        return ent("GEN_OP_VEC_MUL")
    if m.startswith("gf2p8") or m.startswith("crc32"):
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith("k"):
        if m.startswith("kadd"):
            return ent("GEN_OP_VEC_ADD")
        if m.startswith("kshift"):
            return ent("GEN_OP_VEC_LOGIC")
        if m.startswith(("ktest", "kortest")):
            return ent("GEN_OP_TEST")
        if m.startswith("kmov"):
            return ent("GEN_OP_VEC_MOV")
        if m.startswith("knot"):
            return ent("GEN_OP_NOT")
        if m.startswith("kunpck"):
            return ent("GEN_OP_VEC_SHUF")
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith("push"):
        return ent("GEN_OP_PUSH")
    if m == "enter":
        return ent("GEN_OP_PUSH")
    if m.startswith("pop"):
        return ent("GEN_OP_POP")
    if m == "leave":
        return ent("GEN_OP_POP")
    if m.startswith("clflush") or m.startswith(("cldemote", "clwb")):
        return ent("GEN_OP_CACHE_FLUSH", flags="MF_ATOMIC")
    if m.startswith(("invlpg", "invlpga")):
        return ent("GEN_OP_TLB_FLUSH", flags="MF_ATOMIC")
    if m.startswith(("invd", "invept", "invpcid", "invvpid", "wbinvd", "wbnoinvd", "serialize")):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
    # String / REP-prefixable instructions where the underlying
    # classification would otherwise be the LOAD / STORE fall-through:
    # the memory access is incidental, the defining behaviour is the
    # implicit RSI / RDI advance by operand size on every iteration.
    # Caught BEFORE the generic "out* -> STORE" and "in/ins* -> LOAD"
    # rules below.  Specifically NOT included:
    #   - MOVS{B,W,Q}: MOV is itself a specific operation (register-
    #     /memory-data motion), not a generic fall-through; the
    #     pointer advance is a side effect.  Falls through to the
    #     mov* rule below.
    #   - CMPS / SCAS: CMP is a specific operation; pointer advance
    #     does not displace it.  CMPS reaches CMP via the generic
    #     'cmp*' prefix rule further down; SCAS gets its own rule
    #     below.
    if re.match(r"^(stos|lods|ins|outs)[bwq]$", m) \
            or m in {"lodsd", "stosd", "insd", "outsd"}:
        return ent("GEN_OP_INT_ADD")
    if re.match(r"^scas[bwdq]$", m):
        return ent("GEN_OP_CMP")
    if re.match(r"^movs[bwq]$", m):
        return ent("GEN_OP_MOV")
    # Port I/O: exact-match only.  `^out`/`^in(s|$)` regexes were a
    # principle-#1 violation -- "^in(s|$)" greedily matched INSERTPS
    # / INSERTQ ("in" + "s" ...) and mis-filed those SIMD inserts as
    # GEN_OP_LOAD.  The string INS*/OUTS* forms are already handled
    # above (pointer-advance -> INT_ADD); only the bare port ops
    # remain here.
    if m.startswith("xsave") or m.startswith("stmxcsr") or m.startswith(("clrssbsy", "clzero", "ptwrite", "sgdt", "sidt", "wrssd", "wrssq", "wrussd", "wrussq", "xstore")) or m == "out":
        return ent("GEN_OP_STORE")
    if m.startswith("xrstor") or m.startswith("ldmxcsr") or m.startswith(("lgdt", "lidt", "lldt", "llwpcb", "lmsw", "ltr", "rdmsr", "rdpmc", "rstorssp", "sldt", "slwpcb", "smsw", "str")) or m == "in":
        return ent("GEN_OP_LOAD")
    if m.startswith("maskmov"):
        return ent("GEN_OP_STORE")
    if m.startswith(("bndldx", "lds", "les", "lfs", "lgs", "lss", "xlat")):
        return ent("GEN_OP_LOAD")
    if m.startswith("bndstx"):
        return ent("GEN_OP_STORE")
    # Conditional traps: INTO raises only when OF is set, BOUND only when the
    # index is out of range.  Compares that may except -- see the taxonomy note
    # above.
    if m in {"into"} or m.startswith(("bndcl", "bndcu", "bndcn", "bound", "arpl")):
        return ent("GEN_OP_CMP")
    if m.startswith(("bndmk", "bndmov", "lar", "lsl", "lahf", "sahf", "lwpins", "lwpval", "rdfsbase", "rdgsbase", "rdrand", "rdseed", "rdpid", "rdpkru", "rdssp", "saveprevssp", "wrfsbase", "wrgsbase", "wrmsr", "wrpkru")):
        return ent("GEN_OP_MOV")
    if m.startswith(("monitor", "mwait", "umonitor", "umwait", "tpause", "xabort", "xbegin", "xend", "xtest")):
        return ent("GEN_OP_NOP")

    if m.startswith("cmpxchg") or m.startswith("xchg"):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    # XADD atomically exchanges-and-adds.  XCHG would be the wrong
    # classification: functionally the data-mutation is an add, the
    # exchange is just how the result is delivered.  Match the LDADD
    # convention on the other ISAs.
    if m.startswith("xadd"):
        return ent("GEN_OP_INT_ADD", flags="MF_ATOMIC")
    if m.startswith("cmov") or m.startswith("fcmov"):
        return ent("GEN_OP_CMOV")
    if re.match(r"^set[a-z0-9]+$", m):
        return ent("GEN_OP_SETCC")
    if m == "salc":
        return ent("GEN_OP_SETCC")
    if m.startswith(("movsx", "movsxd", "cbw", "cwde", "cdqe", "cwd", "cdq", "cqo")):
        return ent("GEN_OP_MOVSX")
    if m.startswith("movzx"):
        return ent("GEN_OP_MOVZX")
    if m.startswith("lea"):
        return ent("GEN_OP_LEA")
    if m.startswith("mov") or m in {"bswap"}:
        if re.match(r"^mov[a-z]*(ps|pd|dqa|dqu|hp|lp|nt|dq|ap|up|hl|lh|msk|shdup|sldup)", m):
            return ent("GEN_OP_VEC_MOV")
        if re.match(r"^mov[a-z]*s[sd]$", m):
            return ent("GEN_OP_FP_MOV")
        return ent("GEN_OP_MOV")

    if m in {"comisd", "comiss", "ucomisd", "ucomiss"}:
        return ent("GEN_OP_FP_CMP")
    if re.match(r"^(addsub|add|sub|mul|div|sqrt|max|min|cmp|round|cvt)(pd|ps|sd|ss)", m):
        if m.startswith("add"):
            return ent("GEN_OP_FP_ADD")
        if m.startswith("sub"):
            return ent("GEN_OP_FP_SUB")
        if m.startswith("mul"):
            return ent("GEN_OP_FP_MUL")
        if m.startswith("div"):
            return ent("GEN_OP_FP_DIV")
        if m.startswith("sqrt"):
            return ent("GEN_OP_FP_SQRT")
        if m.startswith(("max", "min", "cmp")):
            return ent("GEN_OP_FP_CMP")
        return ent("GEN_OP_FP_CVT")
    if re.match(r"^(and|andn|or|xor)(pd|ps)$", m):
        return ent("GEN_OP_VEC_LOGIC")

    if m.startswith("adc"):
        return ent("GEN_OP_INT_ADD")
    if m.startswith("sbb"):
        return ent("GEN_OP_INT_SUB")
    if m.startswith("add"):
        return ent("GEN_OP_INT_ADD")
    if m.startswith("sub"):
        return ent("GEN_OP_INT_SUB")
    if m.startswith(("imul", "mul")):
        return ent("GEN_OP_INT_MUL")
    if m.startswith(("idiv", "div")):
        return ent("GEN_OP_INT_DIV")
    # BMI2 `pext` is a 4-letter mnemonic and must be matched exactly
    # — `m.startswith("pext")` swallowed SSE4 PEXTRB/PEXTRW/PEXTRD/PEXTRQ
    # (and their VEX/EVEX VPEXTR* equivalents), routing them to GEN_OP_AND
    # instead of the GEN_OP_VEC_SHUF clause that owns element-extract ops.
    # BMI2 PEXT (exact match: m.startswith("pext") would swallow the
    # SSE4 PEXTR* element-extract ops, owned by the VEC_SHUF clause).
    if m == "pext":
        return ent("GEN_OP_BITMANIP")
    # Scalar bit-field / bit-count: extract/deposit/isolate/count
    # bits.  Distinct from the boolean AND/OR/... class (own port,
    # multi-cycle).  AND/ANDN stay boolean.
    if m.startswith(("bextr", "blc", "bls", "t1mskc", "tzmsk",
                      "blsi", "blsmsk", "blsr", "bzhi", "pdep",
                      "popcnt", "lzcnt", "tzcnt", "bsf", "bsr")):
        return ent("GEN_OP_BITMANIP")
    if m.startswith(("and", "andn")):
        return ent("GEN_OP_AND")
    if re.match(r"^or", m):
        return ent("GEN_OP_OR")
    if re.match(r"^xor", m):
        return ent("GEN_OP_XOR")
    if m.startswith("not"):
        return ent("GEN_OP_NOT")
    if m.startswith("neg"):
        return ent("GEN_OP_NEG")
    if m.startswith("inc"):
        return ent("GEN_OP_INC")
    if m.startswith("dec"):
        return ent("GEN_OP_DEC")
    if m.startswith("cmp"):
        return ent("GEN_OP_CMP")
    if m.startswith("test") or re.match(r"^bt[csrt]?$", m):
        return ent("GEN_OP_TEST")
    if m.startswith(("shl", "sal", "shlx")):
        return ent("GEN_OP_SHL")
    if m.startswith(("shr", "shrx")):
        return ent("GEN_OP_SHR")
    if m.startswith(("sar", "sarx")):
        return ent("GEN_OP_SHR")
    if m.startswith(("rol", "rcl")):
        return ent("GEN_OP_ROL")
    if m.startswith(("ror", "rcr")):
        return ent("GEN_OP_ROR")

    if m.startswith("f"):
        if m.startswith(("fnstcw", "fstcw", "fnstsw", "fstsw", "fnstenv", "fstenv", "fnsave", "fsave", "fxsave")):
            return ent("GEN_OP_STORE")
        if m.startswith(("fldcw", "fldenv", "frstor", "fxrstor")):
            return ent("GEN_OP_LOAD")
        if re.match(r"^f(add|iadd)", m):
            return ent("GEN_OP_FP_ADD")
        if re.match(r"^f(sub|isub)", m):
            return ent("GEN_OP_FP_SUB")
        if re.match(r"^f(mul|imul)", m):
            return ent("GEN_OP_FP_MUL")
        if re.match(r"^f(div|idiv)", m):
            return ent("GEN_OP_FP_DIV")
        if m.startswith("fsqrt"):
            return ent("GEN_OP_FP_SQRT")
        if m.startswith(("fcom", "ficom", "ftst", "fucom")):
            return ent("GEN_OP_FP_CMP")
        if m.startswith(("fild", "fist", "fbld", "fbstp")):
            return ent("GEN_OP_FP_CVT")
        return ent("GEN_OP_FP_MOV")

    if m.startswith("v"):
        core = m[1:]
        # VEX aliases of the scalar MXCSR load/store (no SIMD compute).
        if core in {"stmxcsr"}:
            return ent("GEN_OP_STORE")
        if core in {"ldmxcsr"}:
            return ent("GEN_OP_LOAD")
        fma_core = core[1:] if core[:1].isdigit() else core
        if core.startswith("p"):
            p = core[1:]
            if p.startswith("gather"):
                return ent("GEN_OP_VEC_LOAD")
            if p.startswith("scatter"):
                return ent("GEN_OP_VEC_STORE")
            if p.startswith("add"):
                return ent("GEN_OP_VEC_ADD")
            if p.startswith("sub"):
                return ent("GEN_OP_VEC_SUB")
            # VNNI dot-products (VPDPBUSD/VPDPWSSD, VP4DPWSSD with a
            # leading lane-count digit) are multiply-accumulate.
            if p.startswith(("madd", "dp", "4dp")):
                return ent("GEN_OP_VEC_MADD")
            # Carry-less / Galois-field multiply are multiplies, not
            # the VEC_LOGIC fall-through.
            if p.startswith(("clmul", "mul")):
                return ent("GEN_OP_VEC_MUL")
            if p.startswith(("shuf", "blend", "perm", "unpck", "pack", "align", "insert", "extract", "insr", "extr")):
                return ent("GEN_OP_VEC_SHUF")
            if p.startswith(("broadcast", "mov", "load", "store", "maskmov")):
                return ent("GEN_OP_VEC_MOV")
            if p.startswith("test"):
                return ent("GEN_OP_TEST")
            return ent("GEN_OP_VEC_LOGIC")
        if core.startswith(("add", "hadd", "addsub")):
            return ent("GEN_OP_FP_ADD")
        if core.startswith(("sub", "hsub")):
            return ent("GEN_OP_FP_SUB")
        if fma_core.startswith(("fmadd", "fnmadd")) or fma_core.startswith("fmaddsub"):
            return ent("GEN_OP_FP_MADD")
        if fma_core.startswith(("fmsub", "fnmsub")) or fma_core.startswith("fmsubadd"):
            return ent("GEN_OP_FP_MSUB")
        if core.startswith(("mul", "fm", "fnm")):
            return ent("GEN_OP_FP_MUL")
        if core.startswith("div"):
            return ent("GEN_OP_FP_DIV")
        if core.startswith("sqrt"):
            return ent("GEN_OP_FP_SQRT")
        if core.startswith(("cmp", "comi", "ucomi", "max", "min")):
            return ent("GEN_OP_FP_CMP")
        if core.startswith(("cvt", "round")):
            return ent("GEN_OP_FP_CVT")
        # Reciprocal / reciprocal-sqrt approximations (VRCP14*,
        # VRCP28*, VRCPP*, VRSQRT14*, ...): divide- / sqrt-class.
        # Packed (..pd/..ps) -> VEC_*, scalar (..sd/..ss) -> FP_*.
        if core.startswith("rcp"):
            return ent("GEN_OP_FP_DIV" if m.endswith(("sd", "ss"))
                       else "GEN_OP_VEC_DIV")
        if core.startswith("rsqrt"):
            return ent("GEN_OP_FP_SQRT" if m.endswith(("sd", "ss"))
                       else "GEN_OP_VEC_SQRT")
        # Galois-field multiply is a multiply (affine map stays in
        # the VEC_LOGIC fall-through).
        if core.startswith("gf2p8mul"):
            return ent("GEN_OP_VEC_MUL")
        # Gather/scatter: SIMD-indexed memory.  No substantial
        # compute -> the SIMD load/store IS the classification.  The
        # *pf forms only warm cache lines (SIMD prefetch hint).
        if core.startswith(("gatherpf", "scatterpf")):
            return ent("GEN_OP_VEC_PREFETCH")
        if core.startswith("gather"):
            return ent("GEN_OP_VEC_LOAD")
        if core.startswith("scatter"):
            return ent("GEN_OP_VEC_STORE")
        if core.startswith(("mov", "broadcast", "maskmov")):
            return ent("GEN_OP_VEC_MOV")
        if core.startswith(("shuf", "blend", "perm", "unpck", "insert", "extract")):
            return ent("GEN_OP_VEC_SHUF")
        if core.startswith("zero"):
            return ent("GEN_OP_NOP")
        return ent("GEN_OP_VEC_LOGIC")

    if re.match(r"^(addsub|add|sub|mul|div|sqrt|max|min|cmp|round|cvt)[a-z0-9]*[ps][sd]", m):
        if m.startswith("add"):
            return ent("GEN_OP_FP_ADD")
        if m.startswith("sub"):
            return ent("GEN_OP_FP_SUB")
        if m.startswith("mul"):
            return ent("GEN_OP_FP_MUL")
        if m.startswith("div"):
            return ent("GEN_OP_FP_DIV")
        if m.startswith("sqrt"):
            return ent("GEN_OP_FP_SQRT")
        if m.startswith(("max", "min", "cmp")):
            return ent("GEN_OP_FP_CMP")
        return ent("GEN_OP_FP_CVT")
    if m.startswith(("hadd", "padd", "pfacc", "pfadd", "phadd")):
        return ent("GEN_OP_VEC_ADD")
    if m.startswith(("hsub", "pfnacc", "pfpnacc", "pfsub", "psub", "phsub")):
        return ent("GEN_OP_VEC_SUB")
    if m.startswith("pmadd"):
        return ent("GEN_OP_VEC_MADD")
    if m.startswith(("pmul", "montmul", "pfmul")):
        return ent("GEN_OP_VEC_MUL")
    if m.startswith(("blend", "dpp", "extrq", "extract", "insert", "pswap", "pshuf", "pblend", "palign", "punpck", "pack", "pextr", "pinsr", "shuf", "unpck")):
        return ent("GEN_OP_VEC_SHUF")
    if m.startswith(("movap", "movup", "movdq", "movddup", "movshdup", "movsldup", "movhp", "movlp", "lddqu", "pmov")):
        return ent("GEN_OP_VEC_MOV")
    if m.startswith(("pand", "por", "pxor", "pcmp", "pfcm", "pfmax", "pfmin", "phmin", "mpsadbw", "pmin", "pmax", "psad", "pavg", "pabs", "psign", "ptest", "psll", "psrl", "psra")):
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith(("pf2i", "pi2f")):
        return ent("GEN_OP_FP_CVT")
    # Reciprocal -> divide-class; reciprocal-sqrt -> sqrt-class.
    # Packed (..ps/..pd, 3DNow PFRCP/PFRSQ operate on packed) ->
    # VEC_*; scalar (RCPSS/RSQRTSS) -> FP_*.
    if m.startswith(("pfrsq", "rsqrt")):
        return ent("GEN_OP_FP_SQRT" if m.endswith(("ss", "sd"))
                   else "GEN_OP_VEC_SQRT")
    if m.startswith(("pfrcp", "rcp")):
        return ent("GEN_OP_FP_DIV" if m.endswith(("ss", "sd"))
                   else "GEN_OP_VEC_DIV")
    if m in {"sysexitq", "sysret", "sysretq"}:
        return ent("GEN_OP_RET", "BRANCH_RETURN")
    return ent("GEN_OP_UNKNOWN")


def classify_aarch64(m: str) -> Entry:
    if m in {"b"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"bc", "cbz", "cbnz", "tbz", "tbnz"}:
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    if m == "bl":
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_CALL")
    if m.startswith("blr"):
        return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_CALL")
    if m in {"br", "braa", "braaz", "brab", "brabz"}:
        return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
    if m.startswith("ret") or m.startswith("eret"):
        return ent("GEN_OP_RET", "BRANCH_RETURN")
    # Syscalls (svc/hvc/smc/dcps) and unconditional traps (brk/hlt/udf): both
    # always transfer to a vector, so both end a block.  AArch64 has no
    # conditional trap.  See the taxonomy note in classify_x86.
    if m in {"svc", "hvc", "smc", "brk", "hlt", "udf", "dcps1", "dcps2", "dcps3"}:
        return ent("GEN_OP_SYSCALL", "BRANCH_SYSCALL_TYPE")
    if m in {"nop", "hint", "wfe", "wfi", "wfet", "wfit", "sev", "sevl", "yield", "xaflag", "axflag", "cfinv", "gmi", "irg", "rmif"}:
        return ent("GEN_OP_NOP")
    if m in {"dmb", "dsb", "isb", "sb", "csdb", "psb", "tsb", "clrex", "sdsb"}:
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
    # AArch64 has no AARCH64_INS_DC / _IC / _AT / _TLBI constant: Capstone
    # folds the entire DC / IC / AT / TLBI alias space into
    # AARCH64_INS_SYS and distinguishes the members only in the decoded
    # operand detail (and in the mnemonic it prints).  These three rules
    # therefore never fire from the enum sweep; they are kept because they
    # state the intended per-operation mapping, which refine_arm64_sysop
    # applies at decode time.  See the "sys" rule just below.
    if m.startswith(("dc_", "ic_")):
        return ent("GEN_OP_CACHE_FLUSH", flags="MF_ATOMIC")
    if m.startswith("tlbi"):
        return ent("GEN_OP_TLB_FLUSH", flags="MF_ATOMIC")
    if m.startswith("at_"):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
    # SYS / SYSL carry every DC / IC / AT / TLBI operation under the one
    # instruction id.  Cache maintenance is the honest static answer for
    # the family -- it is what all but one member does, and it is a class
    # the attribution lint already knows performs memory work the decoded
    # operands do not show.  refine_arm64_sysop then reads the operands
    # and splits out the members that behave differently, above all
    # DC ZVA, which is a block store rather than maintenance.  Before
    # this rule existed these fell through to the vector catch-all below
    # and came out GEN_OP_VEC_LOGIC, lane-parallel.
    if m in {"sys", "sysl"}:
        return ent("GEN_OP_CACHE_FLUSH", flags="MF_ATOMIC")
    if m.startswith("prf") or m.startswith("rprf") or m.startswith("pli"):
        return ent("GEN_OP_PREFETCH")
    if m.startswith(("sysp", "trcit", "wkdmc", "wkdmd", "rdsvl")):
        return ent("GEN_OP_NOP")

    if m in {"ccmn"}:
        return ent("GEN_OP_CMP")
    # FEAT_MOPS bulk memory set / copy.  These are the ISA's only
    # instructions whose memory fan-out is bounded by nothing but a
    # register — SETM / CPYM transfer the whole page-aligned body of a
    # memset / memcpy in one execution, which glibc routes every
    # memset/memcpy/memmove through on a FEAT_MOPS guest — so no wire
    # slot ceiling can hold one.  BRANCH_REP hands them to the same
    # self-loop fan-out the x86 REP-prefixed string ops use: the
    # instruction becomes its own true BB and its execution is emitted
    # as one body entry per memory access.  See rep_memops_per_iter in
    # champsim_tracer_mnemonics.h for the fan-out unit, which is per
    # memory access here and per architectural element on x86.
    #
    # The prologue form (SETP / CPYP / CPYFP) additionally WRITES NZCV
    # to advertise which implementation option it chose; it does not
    # read it, so it takes no flags dependency.
    if m in {
        "setge", "setgen", "setget", "setgetn", "sete", "seten",
        "setet", "setetn", "setgm", "setgmn", "setgmt", "setgmtn",
        "setgp", "setgpn", "setgpt", "setgptn", "setm", "setmn",
        "setmt", "setmtn", "setp", "setpn", "setpt", "setptn",
    }:
        return ent("GEN_OP_STORE", "BRANCH_REP")
    # The copy half.  Matched by prefix because the option suffixes
    # (read/write x temporal/non-temporal) span 16 spellings per form;
    # the six prefixes below are exact heads of the MOPS copy family
    # and of nothing else (the SVE element copy is the bare "cpy", the
    # SVE FP copy is "fcpy").
    if m.startswith(("cpyp", "cpym", "cpye", "cpyfp", "cpyfm", "cpyfe")):
        return ent("GEN_OP_MOV", "BRANCH_REP")

    if m.startswith(("cas", "casp", "swp")):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if m.startswith(("rcwcas", "rcwscas", "rcwswp", "rcwsswp")):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if m.startswith(("rcwclr", "rcwsclr")):
        return ent("GEN_OP_AND", flags="MF_ATOMIC")
    if m.startswith(("rcwset", "rcwsset")):
        return ent("GEN_OP_OR", flags="MF_ATOMIC")
    if m.startswith(("ldadd", "stadd")):
        return ent("GEN_OP_INT_ADD", flags="MF_ATOMIC")
    if m.startswith(("ldclr", "stclr")):
        return ent("GEN_OP_AND", flags="MF_ATOMIC")
    if m.startswith(("ldeor", "steor")):
        return ent("GEN_OP_XOR", flags="MF_ATOMIC")
    if m.startswith(("ldset", "stset")):
        return ent("GEN_OP_OR", flags="MF_ATOMIC")
    if m.startswith(("ldsmax", "ldsmin", "ldumax", "ldumin", "stsmax", "stsmin", "stumax", "stumin")):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    # Load-exclusive / store-exclusive: single load / single store
    # paired with an exclusive monitor.  Not RMW individually but is
    # an atomic-access primitive in the ISA, so flag MF_ATOMIC.
    # LDAR / LDAPR / LDLAR / STLR / STLLR are memory-ordered single
    # ops — neither RMW nor in the atomic-access category — so they
    # fall through to the plain LOAD / STORE clauses below.
    if m.startswith(("ldxr", "ldaxr", "ldxp", "ldaxp")):
        return ent("GEN_OP_LOAD", flags="MF_ATOMIC")
    if m.startswith(("stxr", "stlxr", "stxp", "stlxp")):
        return ent("GEN_OP_STORE", flags="MF_ATOMIC")
    # NEON / SVE vec loads + stores — by the same convention x86 uses
    # for MOVDQA/MOVAPS (mem<->xmm classifies as GEN_OP_VEC_MOV), any
    # ARM load/store that targets / drains a NEON or SVE vector
    # register is a vector data movement, not a scalar mem op.
    # Covers NEON LD1/LD2/LD3/LD4 (and rep / range variants
    # LD[1-4]R*, LD[1-4]RO*, LD[1-4]RQ*), SVE LD1<elem> / ST1<elem>
    # / LD[2-4]<elem> / ST[2-4]<elem>, and the fault-tolerant /
    # non-temporal forms (LDFF1*, LDNF1*, LDNT1*).
    # NEON structure (LD1..LD4 / ST1..ST4) and SVE contiguous /
    # gather / first-fault / non-fault / non-temporal vector
    # memory.  The SIMD-width memory access IS the defining
    # behaviour and these mnemonics have no scalar form, so they
    # are unambiguously GEN_OP_VEC_LOAD / GEN_OP_VEC_STORE (matches
    # the RVV vle*/vse* convention).  Prefix match (no \b) so the
    # size suffixes (LDFF1SW, LD1RQB, ...) are covered too.
    mv = re.match(r"^(ld|st)(?:[1-4]|ff1|nf1|nt1)", m)
    if mv:
        return ent("GEN_OP_VEC_LOAD" if mv.group(1) == "ld"
                   else "GEN_OP_VEC_STORE")
    if m.startswith(("ld", "ldap", "ldar")):
        return ent("GEN_OP_LOAD")
    if m.startswith("st"):
        return ent("GEN_OP_STORE")

    if m in {"bfm", "mrrs", "mrs", "msr", "msrr", "pmov", "setf16", "setf8"}:
        return ent("GEN_OP_MOV")
    if m.startswith(("adr", "adrp")):
        return ent("GEN_OP_LEA")
    if m.startswith(("aut", "pac", "xpac")):
        return ent("GEN_OP_MOV")
    if m.startswith(("sxt", "sbfm", "sbfiz", "sbfx")):
        return ent("GEN_OP_MOVSX")
    if m.startswith(("uxt", "ubfm", "ubfiz", "ubfx")):
        return ent("GEN_OP_MOVZX")
    # EXT = SIMD "extract from a pair of vectors" (a permute), not a
    # data move; MVNI = vector move-inverted-immediate (a vector
    # set, not bitwise NOT); NEG/NEGS = two's-complement negate.
    # All NEON-only / unambiguous by mnemonic.
    if m in {"ext", "extq"}:
        return ent("GEN_OP_VEC_SHUF")
    if m == "mvni":
        return ent("GEN_OP_VEC_MOV")
    if m in {"neg", "negs"}:
        return ent("GEN_OP_NEG")
    if m.startswith(("dup", "ins", "movi")):
        return ent("GEN_OP_VEC_MOV")
    if m.startswith("extr"):
        # EXTR = scalar bit-field / funnel extract (no NEON form);
        # bit-manipulation class, consistent with x86/MIPS/RISC-V.
        return ent("GEN_OP_BITMANIP")
    if m.startswith(("mov", "movi", "movk", "movn", "movz", "dup", "ins", "ext", "cpy")):
        return ent("GEN_OP_MOV")
    if m in {"clr", "ctz", "pext"}:
        return ent("GEN_OP_AND")
    if m.startswith("gcs"):
        if m.startswith("gcspop"):
            return ent("GEN_OP_POP")
        if m.startswith("gcspush"):
            return ent("GEN_OP_PUSH")
        if m.startswith(("gcsstr", "gcssttr")):
            return ent("GEN_OP_STORE")
        return ent("GEN_OP_MOV")
    if m == "abs":
        return ent("GEN_OP_NEG")
    if m.startswith("adc"):
        return ent("GEN_OP_INT_ADD")
    if re.match(r"^(sadd|uadd|addv|addqv|addp|saba|uaba|sabal|uabal)", m):
        return ent("GEN_OP_VEC_ADD")
    if m.startswith(("madd", "smadd", "umadd")):
        return ent("GEN_OP_INT_MADD")
    if m.startswith(("msub", "smsub", "umsub")):
        return ent("GEN_OP_INT_MSUB")
    if m.startswith(("add", "cmn", "neg", "ngc")):
        return ent("GEN_OP_INT_ADD")
    if re.match(r"^(ssub|usub|subv|sabd|uabd)", m):
        return ent("GEN_OP_VEC_SUB")
    if m.startswith("sbc"):
        return ent("GEN_OP_INT_SUB")
    if m.startswith("sub"):
        return ent("GEN_OP_INT_SUB")
    if m.startswith(("mul", "smul", "umul", "mneg")):
        return ent("GEN_OP_INT_MUL")
    if m.startswith(("sdiv", "udiv")):
        return ent("GEN_OP_INT_DIV")
    if re.match(r"^(andqv|andv)", m):
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith(("and", "bic")):
        return ent("GEN_OP_AND")
    if m.startswith(("orr", "orn")):
        return ent("GEN_OP_OR")
    if m.startswith(("eor", "eon")):
        return ent("GEN_OP_XOR")
    if m.startswith(("mvn", "not")):
        return ent("GEN_OP_NOT")
    if m.startswith(("lsl", "lslrv")):
        return ent("GEN_OP_SHL")
    if m.startswith(("lsr", "lsrrv")):
        return ent("GEN_OP_SHR")
    if m.startswith(("asr", "asrrv")):
        return ent("GEN_OP_SHR")
    if m.startswith(("ror", "rorv", "extr")):
        return ent("GEN_OP_ROR")
    if m.startswith(("cmp", "ccmp")):
        return ent("GEN_OP_CMP")
    if m.startswith(("tst", "ands")):
        return ent("GEN_OP_TEST")
    if m.startswith(("csel", "csinc", "csinv", "csneg", "cinc", "cinv", "cneg")):
        return ent("GEN_OP_CMOV")
    if m.startswith(("cset", "csetm")):
        return ent("GEN_OP_SETCC")

    if m.startswith(("fdot", "fvdot", "bfdot", "bfvdot")):
        return ent("GEN_OP_VEC_MADD")
    if m.startswith(("fcvt", "scvt", "ucvt", "fjcvt", "bfcvt", "bf1cvt", "bf2cvt", "f1cvt", "f2cvt", "fround")):
        return ent("GEN_OP_FP_CVT")
    if m.startswith(("famax", "famin", "fclamp", "bfclamp")):
        return ent("GEN_OP_FP_CMP")
    if m == "fcadd":
        return ent("GEN_OP_FP_ADD")
    if m.startswith(("fadd", "bfadd")):
        return ent("GEN_OP_FP_ADD")
    if m.startswith(("fsub", "bfsub")):
        return ent("GEN_OP_FP_SUB")
    if m.startswith(("fcmla", "fmadd", "fnmadd", "fnmad", "fmad", "fma", "fmla", "fnmla", "fmmla", "fmopa", "bfmla", "bfmmla", "bfmlal", "bfmopa")):
        return ent("GEN_OP_FP_MADD")
    if m.startswith(("fmsub", "fnmsub", "fnmsb", "fms", "fmls", "fnmls", "fmops", "bfmls", "bfmops")):
        return ent("GEN_OP_FP_MSUB")
    if m in {"flogb", "fscale", "ftmad", "ftsmul"}:
        return ent("GEN_OP_FP_MUL")
    if m in {"fmsb"}:
        return ent("GEN_OP_VEC_MUL")
    if m.startswith(("fmul", "fnmul", "bfmul")):
        return ent("GEN_OP_FP_MUL")
    if m.startswith("fdiv"):
        return ent("GEN_OP_FP_DIV")
    if m.startswith("fsqrt"):
        return ent("GEN_OP_FP_SQRT")
    if m.startswith(("facge", "facgt", "fccmp", "fccmpe", "fcmp", "fcm", "fmax", "fmin", "bfmax", "bfmin")):
        return ent("GEN_OP_FP_CMP")
    if m.startswith(("fcsel", "fdup", "fexpa", "flogb", "fscale", "ftmad", "ftssel", "ftsmul", "fmov", "fabs", "fneg", "frint", "frsqr", "frecp")):
        return ent("GEN_OP_FP_MOV")

    # Saturating / rounding / halving / pairwise-accumulate vector
    # add & subtract, and the NEON unsigned reciprocal estimates --
    # all NEON-only mnemonics, were falling into the VEC_LOGIC
    # catch-all below.
    if re.match(r"^(cadd|raddhn|shadd|suqadd|uhadd|usqadd|sqadd"
                r"|uqadd|srhadd|urhadd|sadalp|uadalp|saddlp"
                r"|uaddlp)", m):
        return ent("GEN_OP_VEC_ADD")
    if re.match(r"^(rsubhn|shsub|uhsub|sqsub|uqsub|sqneg)", m):
        return ent("GEN_OP_VEC_SUB")
    if m == "urecpe":
        return ent("GEN_OP_VEC_DIV")
    if m == "ursqrte":
        return ent("GEN_OP_VEC_SQRT")
    if re.match(r"^(bmopa|cmla|mac16|matfp|matint|mla|smlal|umlal|sqdmlal|sqrdmlah|sqrdcmlah|sdot|udot|usdot|sudot|svdot|uvdot|suvdot|usvdot|sumlall|usmlall|mopa|smopa|sumopa|umopa|usmopa|smmla|ummla|usmmla|bfmopa)", m):
        return ent("GEN_OP_VEC_MADD")
    if re.match(r"^(bmops|mls|smlsl|umlsl|sqdmlsl|sqrdmlsh|mops|smops|sumops|umops|usmops|bfmops)", m):
        return ent("GEN_OP_VEC_MSUB")
    if m == "madpt":
        return ent("GEN_OP_VEC_MADD")
    if re.match(r"^(cdot|mad|msb|sqdmul|sqrdmul|mul|pmul|smull|umull)", m):
        return ent("GEN_OP_VEC_MUL")
    if re.match(r"^(clasta|clastb|lasta|lastb|smov|umov)", m):
        return ent("GEN_OP_VEC_MOV")
    if re.match(r"^(genlut|luti|punpk|tbl|tbx|zip|uzp|trn|rev|splice|compact|unpk|uunpk|sunpk|xtn|sqxt|uqxt|uzp|zip|ext|ins|dup|index)", m):
        return ent("GEN_OP_VEC_SHUF")
    if re.match(r"^(aes|bcax|bdep|bext|bgrp|brb|cm|crc32|cterm|dec|drps|fabd|fcpy|genter|gexit|hist|inc|nand|nbsl|nor|orqv|orv|pfirst|pnext|psel|rax1|rdvl|rshr|sadalp|sclamp|set$|sha|sm3|sm4|srsh|srsra|ssh|ssra|sys$|sysl$|tcancel|tcommit|ttest|uadalp|uclamp|ur|ush|usra|vecfp|vecint|while|ptrue|pfalse|rdffr|wrffr|setffr|brk|sel|match|nmatch|ptest|cnt|cls|clz|cnot|eor|orr|and|bic|bsl|bit|bif|xar|rbit|smax|smin|umax|umin|saba|uaba|sabd|uabd|sq|uq|srh|urh|sri|sli|shl|shr|q|uq|sqr|uqr|sqsh|uqsh|sqadd|uqadd|sqsub|uqsub)", m):
        return ent("GEN_OP_VEC_LOGIC")
    if m in {"zero"}:
        return ent("GEN_OP_VEC_LOGIC")
    return ent("GEN_OP_UNKNOWN")


def classify_riscv(m: str) -> Entry:
    if m in {"beq", "bne", "blt", "bge", "bltu", "bgeu", "c_beqz", "c_bnez"}:
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    # jal/jalr link-and-jump: one Capstone insn_id covers both the call
    # (rd != x0, printed "jal"/"jalr") and the plain jump (rd == x0,
    # printed "j"/"jr") and the return (jalr x0,0(ra), printed "ret").
    # The static table can only hold one value per insn_id, so these are
    # DEFAULTS for the linking case; the decoder refines from the live
    # mnemonic alias (see refine_alias_fields in champsim_tracer_decode.cc).
    if m in {"jal", "c_jal"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_CALL")
    if m in {"c_j"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"jalr", "c_jalr"}:
        return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_CALL")
    if m in {"c_jr"}:
        return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
    # ECALL is the syscall; EBREAK and the all-zeros/all-ones UNIMP encodings
    # are unconditional traps (they raise every time).  RISC-V has no
    # conditional trap.  See the taxonomy note in classify_x86.
    if m in {"ecall", "ebreak", "c_ebreak", "unimp", "c_unimp"}:
        return ent("GEN_OP_SYSCALL", "BRANCH_SYSCALL_TYPE")
    if m in {"mret", "sret", "uret", "dret"}:
        return ent("GEN_OP_RET", "BRANCH_RETURN")
    if m in {"sfence_vma", "hfence_gvma", "hfence_vvma", "sinval_vma"}:
        return ent("GEN_OP_TLB_FLUSH", flags="MF_ATOMIC")
    if m.startswith(("fence", "sfence", "hfence")):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
    if m in {"wfi", "pause", "c_nop"} or m.startswith(("mop_", "cmop_")):
        return ent("GEN_OP_NOP")
    if m in {"call", "tail"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_CALL")
    if m in {"jump"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"la", "la_tlsdesc", "la_tls_gd", "la_tls_ie", "lla", "lga", "pcrel_hi", "tlsdesc_hi", "tls_gd_hi", "tls_got_hi", "tls_ie_hi", "auipc"}:
        return ent("GEN_OP_LEA")
    if m in {"li"}:
        return ent("GEN_OP_MOV")
    if m.startswith("csrr"):
        return ent("GEN_OP_MOV")
    if m.startswith("amo"):
        if m.startswith("amoadd"):
            return ent("GEN_OP_INT_ADD", flags="MF_ATOMIC")
        if m.startswith("amoand"):
            return ent("GEN_OP_AND", flags="MF_ATOMIC")
        if m.startswith("amoor"):
            return ent("GEN_OP_OR", flags="MF_ATOMIC")
        if m.startswith("amoxor"):
            return ent("GEN_OP_XOR", flags="MF_ATOMIC")
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    # RISC-V load-reserved / store-conditional: tagged single load /
    # single store, not a swap.  The reservation is a monitor side
    # effect; the pair forms an atomic RMW only when SC sees its
    # reservation intact.  Each instruction is LOAD/STORE with
    # MF_ATOMIC to flag the exclusive-monitor primitive.
    if m.startswith("lr_"):
        return ent("GEN_OP_LOAD", flags="MF_ATOMIC")
    if m.startswith("sc_"):
        return ent("GEN_OP_STORE", flags="MF_ATOMIC")
    if m.startswith("ssamoswap"):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if m.startswith("sspush"):
        return ent("GEN_OP_PUSH")
    if m.startswith("sspop"):
        return ent("GEN_OP_POP")
    if m.startswith("ssrdp"):
        return ent("GEN_OP_MOV")
    if m.startswith(("hlv", "hlvx")):
        return ent("GEN_OP_LOAD")
    if m.startswith("hsv"):
        return ent("GEN_OP_STORE")
    if m.startswith(("cbo_clean", "cbo_flush", "cbo_inval")):
        return ent("GEN_OP_CACHE_FLUSH", flags="MF_ATOMIC")
    if m.startswith("hinval"):
        return ent("GEN_OP_TLB_FLUSH", flags="MF_ATOMIC")
    if m.startswith("wrs_"):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
    if m.startswith("prefetch_"):
        return ent("GEN_OP_PREFETCH")
    if m.startswith("cbo_zero"):
        return ent("GEN_OP_NOP")
    if m.startswith("cm_"):
        if m.startswith("cm_jalt"):
            return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
        if m.startswith("cm_jt"):
            return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
        if m.startswith("cm_push"):
            return ent("GEN_OP_PUSH")
        if m.startswith("cm_popret"):
            return ent("GEN_OP_RET", "BRANCH_RETURN")
        if m.startswith("cm_pop"):
            return ent("GEN_OP_POP")
        return ent("GEN_OP_MOV")
    if m.startswith(("addi", "addiw", "addw", "add", "c_add", "c_addi")):
        return ent("GEN_OP_INT_ADD")
    if m.startswith(("subw", "sub", "c_sub")):
        return ent("GEN_OP_INT_SUB")
    # Zba shift-add (sh1add/sh2add/sh3add[.uw]) is a scaled-index
    # address calc (rs1<<n)+rs2 -- the defining op is the add, like
    # x86 LEA, not a bare shift.
    if m.startswith(("sh1add", "sh2add", "sh3add")):
        return ent("GEN_OP_LEA")
    if m.startswith(("sll", "slli", "c_slli")):
        return ent("GEN_OP_SHL")
    if m.startswith(("srl", "srli", "c_srli")):
        return ent("GEN_OP_SHR")
    if m.startswith(("sra", "srai", "c_srai")):
        return ent("GEN_OP_SHR")
    if m.startswith(("lui", "c_li", "c_lui", "c_mv", "mv")):
        return ent("GEN_OP_MOV")
    if m.startswith(("aes", "brev8", "pack", "unzip", "xperm", "zip")):
        return ent("GEN_OP_AND")
    if m.startswith("czero"):
        return ent("GEN_OP_CMOV")
    if m.startswith(("c_lbu", "c_lh", "c_lhu")):
        return ent("GEN_OP_LOAD")
    if m.startswith(("c_not", "c_sext", "c_zext")):
        return ent("GEN_OP_AND")
    if m.startswith("c_sspush"):
        return ent("GEN_OP_PUSH")
    if m.startswith("c_sspop"):
        return ent("GEN_OP_POP")
    if m.startswith("f"):
        if m.startswith(("fadd",)):
            return ent("GEN_OP_FP_ADD")
        if m.startswith(("fsub", "fsgnj")):
            return ent("GEN_OP_FP_SUB") if m.startswith("fsub") else ent("GEN_OP_FP_MOV")
        if m.startswith(("fmadd", "fnmadd")):
            return ent("GEN_OP_FP_MADD")
        if m.startswith(("fmsub", "fnmsub")):
            return ent("GEN_OP_FP_MSUB")
        if m.startswith(("fmul",)):
            return ent("GEN_OP_FP_MUL")
        if m.startswith("fdiv"):
            return ent("GEN_OP_FP_DIV")
        if m.startswith("fsqrt"):
            return ent("GEN_OP_FP_SQRT")
        if m.startswith(("feq", "flt", "fle", "fmin", "fmax", "fclass")):
            return ent("GEN_OP_FP_CMP")
        if m.startswith(("fcvt", "fround")):
            return ent("GEN_OP_FP_CVT")
        if m.startswith("fmv"):
            return ent("GEN_OP_FP_MOV")
        if m.startswith("fli"):
            return ent("GEN_OP_FP_MOV")
        if m.startswith(("fl",)):
            return ent("GEN_OP_LOAD")
        if m.startswith(("fs",)):
            return ent("GEN_OP_STORE")
        return ent("GEN_OP_FP_MOV")
    if m.startswith(("sha", "sm3", "sm4")):
        return ent("GEN_OP_AND")
    if m.startswith(("lb", "lh", "lw", "ld", "lbu", "lhu", "lwu", "fl", "c_lw", "c_ld", "c_lq", "c_fl")):
        return ent("GEN_OP_LOAD")
    if m.startswith(("sb", "sh", "sw", "sd", "fs", "c_sw", "c_sd", "c_sq", "c_fs", "c_sb", "c_sh")):
        return ent("GEN_OP_STORE")
    if m.startswith(("mul", "c_mul")):
        return ent("GEN_OP_INT_MUL")
    if m.startswith(("div", "rem")):
        return ent("GEN_OP_INT_DIV")
    # Zbb rotates are rotate ops, not AND (the coarse Zb* bucket
    # below would otherwise mis-file them).
    if m.startswith(("rol",)):
        return ent("GEN_OP_ROL")
    if m.startswith(("ror", "rori")):
        return ent("GEN_OP_ROR")
    # Zbc carry-less multiply / Zbb bit-count & friends are bit-
    # manipulation, not boolean AND.
    if m.startswith(("clmul", "clz", "ctz", "cpop", "brev", "bclr",
                     "bext", "binv", "bset", "orc", "rev")):
        return ent("GEN_OP_BITMANIP")
    if m.startswith(("and", "andi", "c_and", "xnor", "sext",
                     "zext")):
        return ent("GEN_OP_AND")
    if m.startswith(("or", "ori", "c_or")):
        return ent("GEN_OP_OR")
    if m.startswith(("xor", "xori", "c_xor")):
        return ent("GEN_OP_XOR")
    if m.startswith(("slt", "sltu", "slti", "sltiu", "min", "max")):
        return ent("GEN_OP_CMP")
    if m.startswith("v"):
        # All RVV loads start "vl" (vle/vlse/vluxei/vloxei/vlseg/
        # vl<n>re/vlm); they move a SIMD-width value -> VEC_LOAD,
        # not the scalar GEN_OP_LOAD.
        if m.startswith("vl"):
            return ent("GEN_OP_VEC_LOAD")
        if m.startswith(("vfcvt", "vfncvt", "vfwcvt")):
            return ent("GEN_OP_FP_CVT")
        if m.startswith(("vset", "vsext")):
            return ent("GEN_OP_VEC_LOGIC")
        if m.startswith(("vadd", "vaadd", "vaaddu", "vadc", "vsadd", "vsaddu", "vwadd", "vfadd", "vfwadd", "vfred", "vwred", "vfwred")):
            return ent("GEN_OP_VEC_ADD")
        if m.startswith(("vsub", "vrsub", "vfrsub", "vasub", "vasubu", "vsbc", "vssub", "vssubu", "vwsub", "vfsub", "vfwsub")):
            return ent("GEN_OP_VEC_SUB")
        if m.startswith(("vmacc", "vmadd", "vwmacc", "vfmacc", "vfnmacc", "vfmadd", "vfnmadd", "vfwmacc", "vfwnmacc")):
            return ent("GEN_OP_VEC_MADD")
        if m.startswith(("vmsac", "vnmsac", "vnmsub", "vfmsac", "vfnmsac", "vfmsub", "vfnmsub", "vfwmsac", "vfwnmsac")):
            return ent("GEN_OP_VEC_MSUB")
        if m.startswith(("vmul", "vsmul", "vwmul", "vfmul", "vfwmul", "vclmul")):
            return ent("GEN_OP_VEC_MUL")
        # Vector divide / modulo / reciprocal: integer (vdiv/vrem),
        # FP (vfdiv/vfrdiv), and the reciprocal estimates
        # (vfrec7 ~ divide-class, vfrsqrt7 ~ sqrt-class).  Were
        # FP_DIV / FP_SQRT (scalar) or the VEC_LOGIC catch-all.
        if m.startswith(("vdivu", "vdiv", "vremu", "vrem",
                         "vfdiv", "vfrdiv", "vfrec")):
            return ent("GEN_OP_VEC_DIV")
        if m.startswith(("vfsqrt", "vfrsqrt")):
            return ent("GEN_OP_VEC_SQRT")
        if m.startswith(("vmerge", "vmv", "vslide", "vrgather", "vcompress", "vfirst", "viota", "vid", "vfmerge", "vfmv")):
            return ent("GEN_OP_VEC_MOV")
        if re.match(r"^vs(e|se|seg|sseg|ox|oxseg|ux|uxseg|[1248]r|m_)", m):
            return ent("GEN_OP_VEC_STORE")
        if m.startswith(("vsha", "vsm3", "vsm4", "vset", "vsext", "vzext", "vsll", "vsra", "vsrl", "vssra", "vssrl", "vcpop", "vms", "vmn", "vmx", "vfmin", "vfmax", "vmseq", "vmsne", "vmslt", "vmsle", "vmsgt", "vmsge", "vmfeq", "vmfne", "vmflt", "vmfle", "vmfgt", "vmfge")):
            return ent("GEN_OP_VEC_LOGIC")
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith("cv_"):
        c = m[3:]
        if c.startswith(("beqimm", "bneimm")):
            return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
        if c.startswith(("lb", "lbu", "lh", "lhu", "lw", "elw")):
            return ent("GEN_OP_LOAD")
        # shuffle/pack/insert/extract BEFORE the store rule: cv.shuffle*
        # otherwise hits the "sh" store-halfword prefix.
        if c.startswith(("pack", "shuffle", "insert", "extract")):
            return ent("GEN_OP_VEC_SHUF")
        if c.startswith(("sb", "sh", "sw")):
            return ent("GEN_OP_STORE")
        if c.startswith(("mac", "mach", "dot", "sdot")):
            return ent("GEN_OP_VEC_MADD")
        if c.startswith("msu"):
            return ent("GEN_OP_VEC_MSUB")
        if c.startswith(("cplxmul", "mul")):
            return ent("GEN_OP_VEC_MUL")
        if c.startswith(("add", "avg")):
            return ent("GEN_OP_VEC_ADD")
        if c.startswith("sub"):
            return ent("GEN_OP_VEC_SUB")
        if c.startswith(("cmp", "slet", "max", "min")):
            return ent("GEN_OP_CMP")
        if c.startswith("and"):
            return ent("GEN_OP_AND")
        if c.startswith("or"):
            return ent("GEN_OP_OR")
        if c.startswith("xor"):
            return ent("GEN_OP_XOR")
        if c.startswith(("sll", "bset", "bclr")):
            return ent("GEN_OP_SHL")
        if c.startswith("srl"):
            return ent("GEN_OP_SHR")
        if c.startswith("sra"):
            return ent("GEN_OP_SHR")
        if c.startswith("ror"):
            return ent("GEN_OP_ROR")
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith("th_"):
        t = m[3:]
        if "cache" in t or t.startswith(("sfence", "sync")):
            return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
        if t.startswith(("lb", "lh", "lw", "ld", "lr", "lur", "fl")):
            return ent("GEN_OP_LOAD")
        if t.startswith(("sb", "sh", "sw", "sd", "sr", "sur", "fs")):
            return ent("GEN_OP_STORE")
        if t.startswith("vmaqa"):
            return ent("GEN_OP_VEC_MADD")
        if t.startswith("mula"):
            return ent("GEN_OP_INT_MADD")
        if t.startswith("muls"):
            return ent("GEN_OP_INT_MSUB")
        if t.startswith("mul"):
            return ent("GEN_OP_INT_MUL")
        if t.startswith("add"):
            return ent("GEN_OP_INT_ADD")
        if t.startswith(("mveqz", "mvnez")):
            return ent("GEN_OP_CMOV")
        if t.startswith("extu"):
            return ent("GEN_OP_MOVZX")
        if t.startswith("ext"):
            return ent("GEN_OP_MOVSX")
        if t.startswith(("ff", "rev", "tst")):
            return ent("GEN_OP_AND")
        return ent("GEN_OP_NOP")
    if m.startswith("sf_"):
        if m.startswith(("sf_vfwmacc", "sf_vqmacc")):
            return ent("GEN_OP_VEC_MADD")
        if m.startswith("sf_vfnrclip"):
            return ent("GEN_OP_FP_CVT")
        return ent("GEN_OP_VEC_MOV")
    return ent("GEN_OP_UNKNOWN")


def classify_mips(m: str) -> Entry:
    # MSA per-element bit ops (BCLR/BNEG/BSET/BINSL/BINSR + i/_df
    # forms) are vector bitwise, NOT branches -- they must beat the
    # "bne"/"b*" branch-prefix rules below (bneg_b -> "bne...").
    # BZ/BNZ (MSA branch-if-(non)zero) are deliberately excluded.
    if m.startswith(("bclr", "bneg", "bset", "binsl", "binsr")):
        return ent("GEN_OP_VEC_LOGIC")
    if m in {"j", "b", "bc", "b16"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"jr", "jrc", "jic", "jr_hb", "jr16", "jrc16", "jrcaddiusp", "jraddiusp"}:
        return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
    if m in {"jal", "bal", "balc", "jalx", "jals"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_CALL")
    if m.startswith(("jalr", "jialc")):
        return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_CALL")
    # The conditional link-and-branch family (BGEZAL / BLTZAL and their
    # likely / short / compact variants).  The `al` suffix IS the link:
    # taken, they write $ra exactly as BAL does, and the `jr $ra` that
    # eventually matches them is a BRANCH_RETURN.  Typed as plain
    # conditional branches they pushed nothing onto a consumer's
    # return-address stack while still popping it, so the RAS drifted by
    # one on every PIC-prologue `bltzal`.  They are calls that may not
    # happen: the taxonomy carries that as BRANCH_DIRECT_CALL plus
    # MF_CONDITIONAL, and the per-entry taken / not-taken outcome tells
    # the consumer whether this one pushed.
    if re.match(r"^b(g|l|eq|ne|lt|ge|gt|le|z|nz).*al", m) and m not in {"bal", "balc"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_CALL", "MF_CONDITIONAL")
    if m.startswith(("bbit", "bposge", "bteqz", "btnez")):
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    if m.startswith(("beq", "bne", "bge", "bgt", "ble", "blt", "bc1", "bc2", "bnv", "bnz", "bz", "bovc", "bnvc")):
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    if m in {"eret", "eretnc", "deret"}:
        return ent("GEN_OP_RET", "BRANCH_RETURN")
    # Conditional traps: the T-family raises only when its comparison holds and
    # has no target field, so fetch runs straight on to the next instruction.
    # Compares that may except -- see the taxonomy note in classify_x86.  Listed
    # exactly rather than by prefix so tlb*/tlbg* keep their own rules.
    if m in {"teq", "tne", "tlt", "tltu", "tge", "tgeu",
             "teqi", "tnei", "tlti", "tltiu", "tgei", "tgeiu"}:
        return ent("GEN_OP_CMP")
    # Syscalls (syscall/hypcall) and unconditional traps (break/sdbbp/sigrie).
    if m.startswith(("syscall", "break", "hypcall", "sdbbp", "sigrie")):
        return ent("GEN_OP_SYSCALL", "BRANCH_SYSCALL_TYPE")
    if m.startswith(("sync", "synci", "pause", "wait", "yield")):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
    if m in {"cache"} or m.startswith("cachee"):
        return ent("GEN_OP_CACHE_FLUSH", flags="MF_ATOMIC")
    if m in {"tlbp", "tlbr", "tlbwi", "tlbwr"} or m.startswith(("ginv", "tlbg", "tlbinv")):
        return ent("GEN_OP_TLB_FLUSH", flags="MF_ATOMIC")
    if m in {"nop", "nop32", "ssnop", "ehb"} or m.startswith(("dmt", "dvp", "dvpe", "emt", "evp", "evpe")):
        return ent("GEN_OP_NOP")
    if m.startswith(("movn", "movz")):
        return ent("GEN_OP_CMOV")
    # MIPS load-linked / store-conditional: tagged single load / single
    # store, not a swap.  The pair forms an atomic RMW only when the
    # SC's monitor is still set, so each individual op is LOAD/STORE
    # with MF_ATOMIC to flag the exclusive-monitor primitive.
    if m in {"ll", "lld", "lle", "llwp"}:
        return ent("GEN_OP_LOAD", flags="MF_ATOMIC")
    if m in {"sc", "scd", "sce", "scwp"}:
        return ent("GEN_OP_STORE", flags="MF_ATOMIC")
    if re.match(r"^c_.*_(s|d|ps)$", m):
        return ent("GEN_OP_FP_CMP")
    if m in {"li", "li16", "dli"} or m.startswith("li_"):
        return ent("GEN_OP_MOV")
    if m in {"la", "dla"}:
        return ent("GEN_OP_LEA")
    if m.startswith("s_"):
        return ent("GEN_OP_STORE")
    if re.match(r"^pref(e|x)?$", m):
        return ent("GEN_OP_PREFETCH")
    if re.match(r"^(lb|lbu|lh|lhu|lw|lwu|ld|lwc[0-9]*|ldc[0-9]*|lux|lwl|lwr|lld|pref|ulh|ulhu|ulw|ualh|ualw|ualwm)($|[0-9]|_|e|x|pc|r|l|m|p|c|$)", m):
        return ent("GEN_OP_LOAD")
    if re.match(r"^(sb|sbx|sh|shx|sw|swc[0-9]*|sdc[0-9]*|sd|sux|swl|swr|sdl|sdr|ush|usw|uash|uasw|uaswm)($|[0-9]|_|e|x|pc|sp|m|p|c|$)", m):
        return ent("GEN_OP_STORE")
    if m.startswith("insert_"):
        return ent("GEN_OP_VEC_SHUF")
    # Scalar bit-field / bit-count / byte-reverse manipulation ->
    # GEN_OP_BITMANIP (own port, multi-cycle; distinct from boolean
    # AND/OR and from plain MOV).  Matched here so it wins over the
    # GPR-move set and the AND fall-through below.  Exact / anchored
    # so MSA insert_/ext_ vector forms (handled elsewhere) are not
    # swallowed.
    if m in {"align", "dalign", "balign", "bitrev", "bitrevw",
             "bitrevh", "byterevw", "wsbh", "dsbh", "dshd",
             "bitswap", "dbitswap", "clz", "clo", "dclz", "dclo",
             "pop", "dpop", "cins", "cins32"} \
            or re.match(r"^d?ext[mu]?$", m) \
            or re.match(r"^d?ins[mu]?$", m) \
            or m.startswith(("extp", "extr", "exts", "append",
                             "prepend")):
        return ent("GEN_OP_BITMANIP")
    if m in {"cfc1", "cfc2", "cfcmsa", "cftc1", "ctc1", "ctc2", "ctcmsa", "cttc1", "di", "ei", "dmfc0", "dmfc2", "dmfgc0", "dmtc0", "dmtc2", "dmtgc0", "mfc0", "mfc2", "mfgc0", "mfhc0", "mfhc1", "mfhc2", "mfhgc0", "mfhi", "mfhi16", "mflo", "mflo16", "mftacx", "mftc0", "mftc1", "mftdsp", "mftgpr", "mfthc1", "mfthi", "mftlo", "mftr", "mtc0", "mtc2", "mtgc0", "mthc0", "mthc1", "mthc2", "mthgc0", "mthi", "mthlip", "mtlo", "mttacx", "mttc0", "mttc1", "mttdsp", "mttgpr", "mtthc1", "mtthi", "mttlo", "mttr", "mtm0", "mtm1", "mtm2", "mtp0", "mtp1", "mtp2", "rdpgpr", "rddsp", "rdhwr", "wrpgpr", "wrdsp"}:
        return ent("GEN_OP_MOV")
    # MSA INSVE (element insert element) is a vector shuffle, not a
    # scalar move -- intercept before the "ins"-prefix MOV rule.
    if m.startswith("insve"):
        return ent("GEN_OP_VEC_SHUF")
    if m.startswith(("move", "dext", "ext", "ins", "dins", "lui")):
        return ent("GEN_OP_MOV")
    if m.startswith(("seb", "seh")):
        return ent("GEN_OP_MOVSX")
    if re.match(r"^(ceil|floor|round|trunc)_(w|l)_(s|d)$", m) or re.match(r"^f(tint|trunc)_(s|u)_(d|w)$", m) or re.match(r"^rint_(s|d|w|l)$", m) or re.match(r"^cvt_(s|d|w|l|ps|pw)_(s|d|w|l|ps|pl|pu|pw)$", m):
        return ent("GEN_OP_FP_CVT")
    fp = re.match(r"^(f?abs|f?add|ceil|c|class|f?div|floor|fmadd|fmsub|f?trunc|maddf|madd|mfc|mov|msubf|msub|f?mul|mulr|f?neg|nmadd|nmsub|recip|round|rsqrt|f?sqrt|f?sub|trunc)_(s|d|w|l|ps|h)$", m)
    if fp:
        stem = fp.group(1)
        if stem in {"fabs", "fadd", "fdiv", "fmadd", "fmsub", "fmul", "fneg", "fsqrt", "fsub"}:
            stem = stem[1:]
        if stem == "add":
            return ent("GEN_OP_FP_ADD")
        if stem == "sub":
            return ent("GEN_OP_FP_SUB")
        if stem in {"fmadd", "maddf", "madd", "nmadd"}:
            return ent("GEN_OP_FP_MADD")
        if stem in {"fmsub", "msubf", "msub", "nmsub"}:
            return ent("GEN_OP_FP_MSUB")
        if stem in {"mul", "mulr"}:
            return ent("GEN_OP_FP_MUL")
        if stem in {"div", "recip"}:
            return ent("GEN_OP_FP_DIV")
        if stem in {"sqrt", "rsqrt"}:
            return ent("GEN_OP_FP_SQRT")
        if stem in {"c", "class"}:
            return ent("GEN_OP_FP_CMP")
        if stem in {"cvt", "ceil", "floor", "round", "trunc"}:
            return ent("GEN_OP_FP_CVT")
        return ent("GEN_OP_FP_MOV")
    if re.match(r"^cmp_.*_(s|d)$", m):
        return ent("GEN_OP_FP_CMP")
    if re.match(r"^fc(eq|le|lt)_(d|w)$", m):
        return ent("GEN_OP_FP_CMP")
    if m in {"maxa_s", "mina_s"}:
        return ent("GEN_OP_FP_CMP")
    if m in {"dmfc1", "dmtc1", "mfc1", "mfhc1", "mtc1", "mthc1", "sel_s"}:
        return ent("GEN_OP_FP_MOV")
    if m in {"aluipc", "auipc"}:
        return ent("GEN_OP_LEA")
    if m.startswith(("aui", "baddu", "dahi", "dati", "daui", "dlsa", "lsa")):
        return ent("GEN_OP_INT_ADD")
    if m.startswith(("maq", "dpau")):
        return ent("GEN_OP_VEC_MADD")
    if m.startswith("dpsu"):
        return ent("GEN_OP_VEC_MSUB")
    if m.startswith(("preceq", "preceu", "precequ")):
        return ent("GEN_OP_VEC_SHUF")
    if m.startswith(("bmnz", "bmz", "bsel", "seleqz", "selnez",
                      "sel")):
        return ent("GEN_OP_CMOV")
    if re.search(r"_(b|h|w|d|ph|qb|v)$", m) or m.startswith(("v", "msa", "copy_", "insert_", "splati", "splat_", "ldi_")):
        if m.startswith("dpadd"):
            return ent("GEN_OP_VEC_MADD")
        if m.startswith("dpsub"):
            return ent("GEN_OP_VEC_MSUB")
        if m.startswith(("add", "hadd", "aver")):
            return ent("GEN_OP_VEC_ADD")
        if m.startswith(("sub", "hsub", "asub")):
            return ent("GEN_OP_VEC_SUB")
        if m.startswith("shll"):
            return ent("GEN_OP_VEC_LOGIC")
        if m.startswith("shra"):
            return ent("GEN_OP_VEC_LOGIC")
        if m.startswith("shrl"):
            return ent("GEN_OP_VEC_LOGIC")
        if m.startswith(("madd", "dotp", "dpadd")):
            return ent("GEN_OP_VEC_MADD")
        if m.startswith(("msub", "dpsub")):
            return ent("GEN_OP_VEC_MSUB")
        if m.startswith(("mul", "dp")):
            return ent("GEN_OP_VEC_MUL")
        # MSA vector divide / modulo / reciprocal-(sqrt).
        if m.startswith(("div", "mod", "fdiv", "frcp")):
            return ent("GEN_OP_VEC_DIV")
        if m.startswith(("fsqrt", "frsqrt")):
            return ent("GEN_OP_VEC_SQRT")
        if m.startswith(("insert", "insve")):
            return ent("GEN_OP_VEC_SHUF")
        if m.startswith(("copy", "ldi", "splat", "splati", "move")):
            return ent("GEN_OP_VEC_MOV")
        if m.startswith(("shf", "ilv", "pck", "sld", "splat", "vshf")):
            return ent("GEN_OP_VEC_SHUF")
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith(("madd", "maddu")):
        return ent("GEN_OP_INT_MADD")
    if m.startswith(("msub", "msubu")):
        return ent("GEN_OP_INT_MSUB")
    if m.startswith(("add", "addu", "dadd", "daddu", "addi", "addiu", "daddi", "daddiu")):
        return ent("GEN_OP_INT_ADD")
    if m.startswith(("sub", "subu", "dsub", "dsubu")):
        return ent("GEN_OP_INT_SUB")
    if m.startswith(("mul", "muh", "dmul", "dmuh", "mult", "dmult")):
        return ent("GEN_OP_INT_MUL")
    if m.startswith(("div", "ddiv", "rem", "drem", "mod", "dmod")):
        return ent("GEN_OP_INT_DIV")
    if m.startswith(("and", "andi", "crc32")):
        return ent("GEN_OP_AND")
    if m.startswith(("or", "ori")):
        return ent("GEN_OP_OR")
    if m.startswith(("xor", "xori")):
        return ent("GEN_OP_XOR")
    if m.startswith(("nor", "not")):
        return ent("GEN_OP_NOT")
    if m.startswith(("shilo", "sll", "dsll")):
        return ent("GEN_OP_SHL")
    if m.startswith(("srl", "dsrl")):
        return ent("GEN_OP_SHR")
    if m.startswith(("sra", "dsra")):
        return ent("GEN_OP_SHR")
    if m.startswith(("rol", "ror", "rotr", "drol", "dror", "drotr", "rotx")):
        return ent("GEN_OP_ROR")
    if m.startswith(("movf", "movt", "movn", "movz", "seleqz", "selnez")):
        return ent("GEN_OP_CMOV")
    if m.startswith(("seq", "sge", "sgt", "sle", "sne", "slt", "sltu", "slti", "sltiu")):
        return ent("GEN_OP_CMP")
    if m in {"balrsc"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"brsc"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m.startswith(("bbeqzc", "bbnezc")):
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    if m.startswith("restore_jrc"):
        return ent("GEN_OP_RET", "BRANCH_RETURN")
    if m.startswith("restore"):
        return ent("GEN_OP_LOAD")
    if m.startswith("save"):
        return ent("GEN_OP_STORE")
    if m in {"abs", "neg"}:
        return ent("GEN_OP_NEG")
    if m in {"max_s", "min_s"}:
        return ent("GEN_OP_VEC_LOGIC")
    if m in {"pll_ps", "plu_ps", "pul_ps", "puu_ps"}:
        return ent("GEN_OP_VEC_SHUF")
    if m.startswith("fork"):
        return ent("GEN_OP_NOP")
    if m.startswith(("saa", "saad")):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if m == "sov":
        return ent("GEN_OP_CMP")
    if m.startswith("cmp"):
        return ent("GEN_OP_CMP")
    return ent("GEN_OP_UNKNOWN")


CLASSIFIERS = {
    "x86": classify_x86,
    "aarch64": classify_aarch64,
    "riscv": classify_riscv,
    "mips": classify_mips,
}


def classify(info: IsaInfo, const_name: str) -> Entry:
    return CLASSIFIERS[info.key](c_mnemonic(const_name, info.prefix))


def format_entry(const_name: str, entry: Entry) -> str:
    # Dense designated array init: [CONST] = { .field = ..., ... }
    # for every enum value, with empty {} placeholders for the
    # unclassified slots (see format_empty_entry).  Dense means
    # g++ accepts the table; the array designator means the table
    # stays robust against Capstone enum-value shifts (a new insn
    # inserted in the middle of the enum re-aligns automatically
    # instead of silently mis-mapping every subsequent slot).
    left = f"    [{const_name}]"
    pad1 = " " * max(1, 36 - len(const_name))
    pad2 = " " * max(1, 14 - len(entry.op))
    pad3 = " " * max(1, 22 - len(entry.branch))
    head = (f"{left}{pad1}= {{ "
            f".opcode = {entry.op},{pad2}"
            f".branch_type = {entry.branch},{pad3}"
            f".flags = {entry.flags}")
    extras: list[str] = []
    if entry.refine:
        extras.append(f".refine = {entry.refine}")
    if entry.dep_refine:
        extras.append(f".dep_refine = {entry.dep_refine}")
    if entry.lane_mask_kind != "LANE_MASK_KIND_NONE":
        extras.append(f".lane_mask_kind = {entry.lane_mask_kind}")
        # Emit lane_parallel explicitly (true or false) on vec rows so
        # the cross-lane classification is greppable / scannable.
        # The struct default is false, but readers shouldn't have to
        # infer cross-lane from absence.
        extras.append(f".lane_parallel = {'true' if entry.lane_parallel else 'false'}")
    if not extras:
        return head + " },"
    indent = " " * 40
    suffix = "".join(f",\n{indent}{e}" for e in extras)
    return head + suffix + " },"


def format_empty_entry(const_name: str) -> str:
    # Placeholder slot for an enum value we don't classify.  Carries
    # the array designator so the surrounding entries stay enum-
    # indexed; dense + designated keeps g++ happy. */
    return f"    [{const_name}]{' ' * max(1, 36 - len(const_name))}= {{}},"


def xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


@lru_cache(maxsize=None)
def gdb_xml_feature(xml_name: str) -> GdbXmlFeature:
    path = GDB_XML_DIR / xml_name
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError as exc:
        raise SystemExit(f"could not find GDB XML feature {path}") from exc
    except ET.ParseError as exc:
        raise SystemExit(f"could not parse GDB XML feature {path}: {exc}") from exc

    regnum = 0
    parsed: list[tuple[str, int]] = []
    for child in root:
        if xml_local_name(child.tag) != "reg":
            continue
        if "regnum" in child.attrib:
            regnum = int(child.attrib["regnum"], 0)
        parsed.append((child.attrib["name"], regnum))
        regnum += 1

    if not parsed:
        return GdbXmlFeature(root.attrib["name"], {}, (), 0)

    base_reg = min(regnum for _, regnum in parsed)
    num_regs = max(regnum for _, regnum in parsed) - base_reg + 1
    regs: dict[str, int] = {}
    names_by_local: list[str | None] = [None] * num_regs
    for name, regnum in parsed:
        local_reg = regnum - base_reg
        regs[name] = local_reg
        names_by_local[local_reg] = name
    return GdbXmlFeature(root.attrib["name"], regs, tuple(names_by_local), num_regs)


def gdb_xml_reg_name(xml_name: str, local_reg: int) -> str | None:
    names = gdb_xml_feature(xml_name).names_by_local
    return names[local_reg] if 0 <= local_reg < len(names) else None


def add_qemu_reg_key(regs: dict[str, QemuRegKey], name: str,
                     feature_name: str, qemu_name: str | None = None) -> None:
    regs[name] = QemuRegKey(feature_name, qemu_name or name)


def add_gdb_feature_keys(regs: dict[str, QemuRegKey],
                         feature: GdbXmlFeature) -> None:
    for name in feature.regs:
        add_qemu_reg_key(regs, name, feature.feature_name)


@lru_cache(maxsize=None)
def gdb_xml_reg_key_map(xml_names: tuple[str, ...]) -> dict[str, QemuRegKey]:
    regs: dict[str, QemuRegKey] = {}
    for xml_name in xml_names:
        add_gdb_feature_keys(regs, gdb_xml_feature(xml_name))
    return regs


def add_sequential_qemu_reg_keys(regs: dict[str, QemuRegKey], prefix: str,
                                 count: int, feature_name: str) -> None:
    for num in range(count):
        add_qemu_reg_key(regs, f"{prefix}{num}", feature_name)


@lru_cache(maxsize=None)
def qemu_x86_reg_keys() -> dict[str, QemuRegKey]:
    return gdb_xml_reg_key_map(("i386-64bit.xml",))


@lru_cache(maxsize=None)
def qemu_aarch64_reg_keys() -> dict[str, QemuRegKey]:
    regs = dict(gdb_xml_reg_key_map(("aarch64-core.xml", "aarch64-fpu.xml")))
    sve_feature = "org.gnu.gdb.aarch64.sve"

    add_sequential_qemu_reg_keys(regs, "z", 32, sve_feature)
    add_sequential_qemu_reg_keys(regs, "p", 16, sve_feature)
    add_qemu_reg_key(regs, "ffr", sve_feature)
    add_qemu_reg_key(regs, "vg", sve_feature)
    return regs


# The Zicsr control and status registers QEMU exposes.  Unlike the GPR
# and FPR files these have no static GDB XML: target/riscv/gdbstub.c
# builds "org.gnu.gdb.riscv.csr" at CPU-realize time from csr_ops[],
# naming each register the way the ISA does, so the names are listed
# here rather than parsed out of gdb-xml/.
#
# Only the ones Capstone gives a register id (riscv.h: RISCV_REG_FFLAGS
# .. RISCV_REG_VXSAT) can be reached from this table; the rest of the
# CSR space arrives as a QEMU_PLUGIN_OP_SYSREG operand and is resolved
# from the operand's own name at decode time.  RISCV_REG_SSP is absent
# on purpose: Zicfiss's `ssp` is not in the predicate-gated CSR list
# QEMU registers, so there is no register to read and the row stays
# unmapped rather than borrowing another CSR's content.
QEMU_RISCV_CSR_FEATURE = "org.gnu.gdb.riscv.csr"
QEMU_RISCV_CSR_NAMES = (
    "fflags", "frm", "vl", "vtype", "vxrm", "vxsat", "vlenb",
)


@lru_cache(maxsize=None)
def qemu_riscv_reg_keys() -> dict[str, QemuRegKey]:
    regs = dict(gdb_xml_reg_key_map(("riscv-64bit-cpu.xml", "riscv-64bit-fpu.xml")))
    add_sequential_qemu_reg_keys(regs, "v", 32, "org.gnu.gdb.riscv.vector")
    for name in QEMU_RISCV_CSR_NAMES:
        add_qemu_reg_key(regs, name, QEMU_RISCV_CSR_FEATURE)
    return regs


# MIPS' whole GDB-stub namespace is one feature and one XML file, so
# unlike the other three it needs no synthesised additions: what
# mips64-cpu.xml lists is what qemu_plugin_get_registers() reports.
# qemu_mips_reg_key() below RENAMES into this namespace (Capstone's
# HI0 -> `hi`, D<n> -> the `f<2n>`/`f<n>` pair member); this map is the
# namespace ITSELF, which is what the QEMU-indexed table is keyed on.
@lru_cache(maxsize=None)
def qemu_mips_reg_keys() -> dict[str, QemuRegKey]:
    return gdb_xml_reg_key_map(("mips64-cpu.xml",))


QEMU_REG_KEYS = {
    "x86": qemu_x86_reg_keys,
    "aarch64": qemu_aarch64_reg_keys,
    "riscv": qemu_riscv_reg_keys,
    "mips": qemu_mips_reg_keys,
}


def qemu_reg_key_by_name(isa: str, name: str | None) -> QemuRegKey | None:
    if name is None:
        return None
    return QEMU_REG_KEYS[isa]().get(name)


def qemu_x86_reg_key(name: str) -> QemuRegKey | None:
    gpr_aliases = {
        "A": "rax", "B": "rbx", "C": "rcx", "D": "rdx",
        "SI": "rsi", "DI": "rdi", "BP": "rbp", "SP": "rsp",
    }
    if name in {"EIZ", "RIZ"}:
        return None
    if name in {"IP", "EIP", "RIP"}:
        return qemu_reg_key_by_name("x86", "rip")
    if name == "EFLAGS":
        return qemu_reg_key_by_name("x86", "eflags")
    if name == "FPSW":
        return qemu_reg_key_by_name("x86", "fstat")
    segs = {"CS", "SS", "DS", "ES", "FS", "GS"}
    if name in segs:
        return qemu_reg_key_by_name("x86", name.lower())
    if match := re.fullmatch(r"CR(0|2|3|4|8)", name):
        return qemu_reg_key_by_name("x86", f"cr{match.group(1)}")
    if match := re.fullmatch(r"(?:FP|ST)([0-7])", name):
        return qemu_reg_key_by_name("x86", f"st{match.group(1)}")
    if match := re.fullmatch(r"[XYZ]MM(\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("x86", f"xmm{num}") if num < 16 else None
    if name == "MXCSR":
        return qemu_reg_key_by_name("x86", "mxcsr")
    if match := re.fullmatch(r"R(\d+)(?:[BDW])?", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("x86", f"r{num}") if 8 <= num <= 15 else None
    for base, qemu_name in gpr_aliases.items():
        if re.fullmatch(rf"[ER]?{base}[XHL]?|{base}L", name):
            return qemu_reg_key_by_name("x86", qemu_name)
    return None


def qemu_aarch64_reg_key(name: str) -> QemuRegKey | None:
    if name in {"X_LANE", "Y_LANE", "WZR", "XZR"}:
        return None
    if name in {"SP", "WSP"}:
        return qemu_reg_key_by_name("aarch64", "sp")
    if name == "LR":
        return qemu_reg_key_by_name("aarch64", "x30")
    if name == "FP":
        return qemu_reg_key_by_name("aarch64", "x29")
    if name == "NZCV":
        return qemu_reg_key_by_name("aarch64", "cpsr")
    if name == "FPSR":
        return qemu_reg_key_by_name("aarch64", "fpsr")
    if name == "FPCR":
        return qemu_reg_key_by_name("aarch64", "fpcr")
    if name == "FFR":
        return qemu_reg_key_by_name("aarch64", "ffr")
    if name == "VG":
        return qemu_reg_key_by_name("aarch64", "vg")
    if match := re.fullmatch(r"P(\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("aarch64", f"p{num}") if num < 16 else None
    if match := re.fullmatch(r"[BHSDQ](\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("aarch64", f"v{num}") if num < 32 else None
    if match := re.fullmatch(r"Z(\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("aarch64", f"z{num}") if num < 32 else None
    if match := re.fullmatch(r"[WX](\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("aarch64", f"x{num}") if num < 31 else None
    return None


def qemu_riscv_reg_key(name: str) -> QemuRegKey | None:
    if name in {"DUMMY_REG_PAIR_WITH_X0"}:
        return None
    if name == "X0_PAIR":
        return None
    if name.lower() in QEMU_RISCV_CSR_NAMES:
        return qemu_reg_key_by_name("riscv", name.lower())
    if match := re.fullmatch(r"X(\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name(
            "riscv", gdb_xml_reg_name("riscv-64bit-cpu.xml", num)) if num < 32 else None
    if match := re.fullmatch(r"F(\d+)_[DFH]", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name(
            "riscv", gdb_xml_reg_name("riscv-64bit-fpu.xml", num)) if num < 32 else None
    if match := re.fullmatch(r"V(\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("riscv", f"v{num}") if num < 32 else None
    return None


# The three CP0 registers QEMU's MIPS gdbstub carries (mips-cpu.xml:
# status, badvaddr, cause).  The rest of the CP0 file, the DSP
# accumulators above AC0, the DSPControl word, the FCC condition bits
# and the MSA vector file are absent from the descriptor list
# altogether, so their rows stay unmapped: there is no register to read.
# Both spellings Capstone uses for each reach the same register --- the
# bare CP0 number and the named `cop0sel_` form.
QEMU_MIPS_CP0_NAMES = {
    "COP08": "badvaddr",
    "COP0SEL_BADVADDR": "badvaddr",
    "COP012": "status",
    "COP0SEL_STATUS": "status",
    "COP013": "cause",
    "COP0SEL_CAUSE": "cause",
}


def qemu_mips_reg_key(name: str) -> QemuRegKey | None:
    feature = "org.gnu.gdb.mips.cpu"
    if name in QEMU_MIPS_CP0_NAMES:
        return QemuRegKey(feature, QEMU_MIPS_CP0_NAMES[name])
    gpr_names = (
        "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
        "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
        "t8", "t9", "k0", "k1", "gp", "sp", "s8", "ra",
    )
    stem = re.sub(r"(?:_NM|_64)$", "", name)
    if stem == "ZERO":
        return QemuRegKey(feature, "zero")
    if stem == "PC":
        return QemuRegKey(feature, "pc")
    # The architectural HI/LO pair is Capstone's HI0/LO0 (there is no
    # bare MIPS_REG_HI or MIPS_REG_LO, so keying on "HI"/"LO" bound
    # nothing and left the whole accumulator class unbound in the
    # collision audit).  HI1-3/LO1-3 are the DSP ASE accumulators and
    # QEMU's GDB stub does not name them.
    if stem == "LO0":
        return QemuRegKey(feature, "lo")
    if stem == "HI0":
        return QemuRegKey(feature, "hi")
    if stem in MIPS_GPR_NUM:
        return QemuRegKey(feature, gpr_names[MIPS_GPR_NUM[stem]])
    if match := re.fullmatch(r"F(\d+)", stem):
        num = int(match.group(1))
        return QemuRegKey(feature, f"f{num}") if num < 32 else None
    # See classify_mips_reg: an FR=0 double is the pair starting at
    # $f<2n>, an FR=1 double is $f<n>.  The GDB-stub name has to follow,
    # or a value read for `D1` would fetch $f1 instead of $f2.
    if match := re.fullmatch(r"D(\d+)", stem):
        num = int(match.group(1))
        if not name.endswith("_64"):
            num *= 2
        return QemuRegKey(feature, f"f{num}") if num < 32 else None
    if stem == "FCR31":
        return QemuRegKey(feature, "fcr31")
    if stem == "FCR0":
        return QemuRegKey(feature, "fcr0")
    return None


QEMU_REG_CLASSIFIERS = {
    "x86": qemu_x86_reg_key,
    "aarch64": qemu_aarch64_reg_key,
    "riscv": qemu_riscv_reg_key,
    "mips": qemu_mips_reg_key,
}


def qemu_reg_key(info: IsaInfo, const_name: str) -> QemuRegKey | None:
    name = const_name.removeprefix(info.reg_prefix)
    return QEMU_REG_CLASSIFIERS[info.key](name)


def c_string(value: str) -> str:
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def format_qemu_reg(qemu_reg: QemuRegKey | None) -> str:
    if qemu_reg is None:
        return ""
    return (", .qemu_reg = { .feature = " + c_string(qemu_reg.feature) +
            ", .name = " + c_string(qemu_reg.name) + " }")


def format_reg_entry(const_name: str, entry: RegEntry, comment: str,
                     qemu_reg: QemuRegKey | None) -> str:
    # Dense designated array init — see format_entry's comment.
    qemu_field = format_qemu_reg(qemu_reg)
    flags_field = ", .is_int_flags = true" if entry.is_int_flags else ""
    if entry.aliases:
        aliases = ", ".join(entry.aliases)
        return (f"    [{const_name}] = {{ .reg_id = {entry.primary}, "
                f".n_regs = {len(entry.aliases)}, .regs = {{ {aliases} }}"
                f"{qemu_field}{flags_field} }},  /* {comment} */")
    return (f"    [{const_name}] = {{ .reg_id = {entry.primary}"
            f"{qemu_field}{flags_field} }},  /* {comment} */")


def format_empty_reg_entry(const_name: str) -> str:
    return f"    [{const_name}] = {{}},"


def full_entry(info: IsaInfo, const_name: str,
               existing: dict[str, Entry]) -> Entry | None:
    """The COMPLETE classification of one Capstone constant.

    Every field an InsnClassification row carries -- opcode, branch
    type, flags, .refine, .dep_refine and the lane pair -- assembled in
    one place.  It is factored out of generated_body because the
    QEMU-identity tables carry the same payload under a different key,
    and a second copy of this assembly would be a second answer: a row
    that grew a .dep_refine under one key and not the other is the
    exact defect a single source of truth exists to make impossible.

    Returns None when the constant carries no classification at all.
    """
    new = classify(info, const_name)
    old = existing.get(const_name)
    if new.op == "GEN_OP_UNKNOWN" and old is None:
        return None
    if new.op == "GEN_OP_UNKNOWN" and old is not None:
        new = old.without_refine()
    refine = old.refine if old and old.refine else None
    # Classifier-driven .refine: AArch64 has one Capstone insn id
    # per mnemonic for both the scalar-FP and packed-vector forms
    # (FDIV Dd vs FDIV Vd.2D).  The static table classifies the
    # scalar FP_* op; refine_arm64_fp_vec promotes it to the VEC_*
    # twin at decode when the operands show a vector arrangement.
    # Only fills an otherwise-empty .refine (manual fixups win).
    if (refine is None and info.key == "aarch64"
            and new.op in FP_VEC_PROMOTE_OPS):
        refine = "refine_arm64_fp_vec"
    # AArch64 CMP / CMN / TST are aliases for the flag-writing
    # SUBS / ADDS / ANDS forms with the destination register set
    # to XZR / WZR.  Capstone returns the underlying SUBS/ADDS/ANDS
    # insn id, so the static table picks GEN_OP_INT_SUB /
    # GEN_OP_INT_ADD / GEN_OP_AND.  refine_arm64_cmp_alias detects
    # the flag-only shape (REG_ZERO is the only register dst) and
    # promotes opcode to CMP / TEST.  Only fills empty .refine.
    if (refine is None and info.key == "aarch64"
            and const_name in CMP_ALIAS_PROMOTE_INSNS):
        refine = "refine_arm64_cmp_alias"
    dep_refine = classify_dep_refine(info, const_name, new)
    lane_kind, lane_par = classify_lane_info(info, const_name, new.op)
    return Entry(new.op, new.branch, new.flags, refine, dep_refine,
                 lane_kind, lane_par)


def generated_body(info: IsaInfo, constants: list[str], existing: dict[str, Entry]) -> str:
    """Render the InsnClassification table body.

    .refine annotations are preserved across regenerations (long-
    standing behavior; rows pick up manual ISA-specific fixups).
    .dep_refine is owned by the Capstone-source-driven classifier
    (classify_dep_refine) and rewritten on every --apply — so when
    the classifier or refiner library evolves, the rewrite propagates
    fresh decisions across the whole table.  If per-row manual
    .dep_refine overrides become useful, add a separate marker
    (comment annotation or sibling field) so they're distinguishable
    from classifier output.
    """
    lines = [f"    /* Auto-generated by {Path(__file__).name}. */"]
    emitted = 0
    dep_assigned = 0
    # Emit one entry per enum value in declaration order, dense (no
    # gaps).  Unclassified slots get a {} placeholder so g++ accepts
    # the array init.  enum_constants excludes INVALID; the leading
    # placeholder makes slot 0 explicit so g++ sees the table fully
    # initialised. */
    lines.append(format_empty_entry(info.prefix + "INVALID"))
    for const_name in constants:
        new = full_entry(info, const_name, existing)
        if new is None:
            lines.append(format_empty_entry(const_name))
            continue
        if new.dep_refine:
            dep_assigned += 1
        lines.append(format_entry(const_name, new))
        emitted += 1
    lines.insert(1, f"    /* {info.key}: {emitted}/{len(constants) + 1} classified, "
                    f"{len(constants) - emitted} unknown, "
                    f"{dep_assigned}/{emitted} with .dep_refine */")
    return "\n".join(lines) + "\n"


def generated_reg_body(info: IsaInfo, constants: list[str]) -> str:
    lines = [f"    /* Auto-generated by {Path(__file__).name}. */"]
    mapped = 0
    ignored = 0
    # Dense positional list (no array designators) so g++ accepts
    # the table when compiled as C++.  Unmapped/ignored slots emit
    # a {} placeholder to keep the list aligned with the enum.
    # The leading INVALID slot lands at index 0 explicitly since
    # enum_reg_constants excludes it (its classifier path recurses).
    lines.append(format_empty_reg_entry(info.reg_prefix + "INVALID"))
    for const_name in constants:
        entry = classify_reg(info, const_name)
        if entry.ignored:
            ignored += 1
            lines.append(format_empty_reg_entry(const_name))
            continue
        mapped += 1
        comment = const_name.removeprefix(info.reg_prefix).lower()
        lines.append(format_reg_entry(const_name, entry, comment,
                                      qemu_reg_key(info, const_name)))
    lines.insert(1, f"    /* {info.key} regs: {mapped}/{len(constants) + 1} mapped, {ignored} intentionally ignored */")
    return "\n".join(lines) + "\n"


def targeted_fix(isa: str, const_name: str, old: Entry, new: Entry) -> bool:
    if new.op == "GEN_OP_UNKNOWN":
        return False
    if new.op in MADD_OPS and old.op != new.op:
        return True
    if new.branch == "BRANCH_COND_DIRECT" and old.without_refine() != new:
        return True
    if old.op == "GEN_OP_NOP" and new.op == "GEN_OP_FENCE":
        return True
    if old.op == "GEN_OP_STORE" and new.op in {"GEN_OP_VEC_LOGIC", "GEN_OP_VEC_SHUF"}:
        return True
    if old.op == "GEN_OP_LOAD" and new.op in {"GEN_OP_VEC_MOV", "GEN_OP_VEC_LOGIC"}:
        return True
    if old.op == "GEN_OP_FP_MOV" and new.op == "GEN_OP_FP_CVT":
        return True
    if old.op == "GEN_OP_VEC_LOGIC" and new.op in {"GEN_OP_FP_DIV", "GEN_OP_FP_SQRT"}:
        return True
    if isa == "x86":
        return const_name in {
            "X86_INS_JCXZ", "X86_INS_JECXZ", "X86_INS_JRCXZ",
            "X86_INS_LOOP", "X86_INS_LOOPE", "X86_INS_LOOPNE",
            "X86_INS_INT3", "X86_INS_MOVSB", "X86_INS_MOVSW",
            "X86_INS_MOVSQ", "X86_INS_MOVSLDUP", "X86_INS_SALC",
        }
    if isa == "aarch64":
        if const_name.startswith(("AARCH64_INS_AUT", "AARCH64_INS_PAC", "AARCH64_INS_XPAC")):
            return True
        if const_name == "AARCH64_INS_UXTW":
            return True
        if const_name.startswith("AARCH64_INS_BFCVT"):
            return True
        return False
    if isa == "mips":
        if const_name.startswith("MIPS_INS_ASUB") or const_name.startswith("MIPS_INS_INSERT_"):
            return True
        return False
    return False


def audit_one(info: IsaInfo, *, max_lines: int) -> int:
    constants = enum_constants(info)
    existing = parse_existing(info)
    missing: list[tuple[str, Entry]] = []
    mismatched: list[tuple[str, Entry, Entry]] = []
    stale = [name for name in sorted(existing) if name not in constants]
    unknown_existing: list[str] = []
    dep_histogram: dict[str, int] = {}
    dep_affirmative_count: int = 0      # rows the classifier picked positively
    dep_fallback_rows: list[tuple[str, str]] = []   # (const_name, op)
    dep_missing_refiner: list[tuple[str, str]] = []  # (const, refiner)
    dep_unknown_refiner: list[tuple[str, str]] = []  # (const, refiner)
    dep_all_degenerate_rows: list[tuple[str, str]] = []  # (const_name, op)
    for const_name in constants:
        new = classify(info, const_name)
        old = existing.get(const_name)
        if old is None:
            if new.op != "GEN_OP_UNKNOWN":
                missing.append((const_name, new))
            continue
        if new.op == "GEN_OP_UNKNOWN":
            unknown_existing.append(const_name)
            continue
        if old.without_refine() != new:
            mismatched.append((const_name, old, new))
        # Dep-coverage tally.  Rows are assigned a refiner and
        # accounted as either affirmative (classifier had positive
        # evidence) or fallback (every classifier missed).
        if old.dep_refine is None:
            dep_missing_refiner.append((const_name, "(missing)"))
            continue
        dep_histogram[old.dep_refine] = \
            dep_histogram.get(old.dep_refine, 0) + 1
        if old.dep_refine not in DEP_REFINERS:
            dep_unknown_refiner.append((const_name, old.dep_refine))
        _, affirmative = classify_dep_refine_explicit(info, const_name, new)
        if affirmative:
            dep_affirmative_count += 1
        else:
            dep_fallback_rows.append((const_name, old.op))
        # Flag canonicals where Capstone's source tables systematically
        # under-tag every variant (only "degenerate" access lists with
        # no dst).  These get an affirmative dep_all_to_all assignment
        # as a conservative-correct workaround, but the underlying
        # Capstone-side gap is upstream worth reporting.
        cap_vs = _variants_by_canonical(info.key).get(const_name)
        if cap_vs and all(_is_degenerate_variant(v) for v in cap_vs):
            dep_all_degenerate_rows.append((const_name, old.op))

    classified = len({name for name in constants if classify(info, name).op != "GEN_OP_UNKNOWN"})
    print(f"{info.key}: constants={len(constants) + 1} classified_by_rules={classified} existing={len(existing)} missing={len(missing)} mismatched={len(mismatched)} stale={len(stale)}")
    if missing:
        print("  missing:")
        for const_name, new in missing[:max_lines]:
            print(f"    {const_name}: {new.op}, {new.branch}, {new.flags}")
        if len(missing) > max_lines:
            print(f"    ... {len(missing) - max_lines} more")
    if mismatched:
        print("  mismatched:")
        for const_name, old, new in mismatched[:max_lines]:
            print(f"    {const_name}: {old.op}/{old.branch}/{old.flags} -> {new.op}/{new.branch}/{new.flags}")
        if len(mismatched) > max_lines:
            print(f"    ... {len(mismatched) - max_lines} more")
    if stale:
        print("  stale constants not in current Capstone header:")
        for const_name in stale[:max_lines]:
            print(f"    {const_name}")
        if len(stale) > max_lines:
            print(f"    ... {len(stale) - max_lines} more")
    if unknown_existing:
        print(f"  existing entries with no rule coverage: {len(unknown_existing)}")

    # Dep-refiner coverage report.  Every row carries an explicit
    # refiner; rows where the classifier had positive evidence count
    # as "covered" (precise OR affirmative-all-to-all), while rows
    # the classifier couldn't place show up in the precision-gap
    # list grouped by GenericOpcode.
    dep_total = sum(dep_histogram.values()) + len(dep_missing_refiner)
    n_fallback = len(dep_fallback_rows)
    print(f"  dep coverage: {dep_affirmative_count}/{dep_total} classified, "
          f"{n_fallback} fallback, "
          f"{len(dep_missing_refiner)} missing assignment")
    for refiner in sorted(dep_histogram):
        marker = "  (catch-all)" if refiner == DEFAULT_DEP_REFINE else ""
        print(f"    {refiner}: {dep_histogram[refiner]}{marker}")
    if dep_unknown_refiner:
        print(f"  WARNING: rows referencing unknown refiner names "
              f"({len(dep_unknown_refiner)}):")
        for const_name, refiner in dep_unknown_refiner[:max_lines]:
            print(f"    {const_name}: {refiner}")
        if len(dep_unknown_refiner) > max_lines:
            print(f"    ... {len(dep_unknown_refiner) - max_lines} more")
    if dep_missing_refiner:
        print(f"  WARNING: rows with no .dep_refine assignment "
              f"({len(dep_missing_refiner)}) — re-run --apply to fill")
    if dep_fallback_rows and max_lines > 0:
        # Group by GenericOpcode so the precision gap is actionable
        # (each group suggests a candidate refiner or classifier rule).
        by_op: dict[str, list[str]] = {}
        for const_name, op in dep_fallback_rows:
            by_op.setdefault(op, []).append(const_name)
        print(f"  precision gap — rows the classifier couldn't place (by op):")
        for op in sorted(by_op, key=lambda k: (-len(by_op[k]), k)):
            sample = ", ".join(by_op[op][:4])
            more = "" if len(by_op[op]) <= 4 else f", ... +{len(by_op[op]) - 4}"
            print(f"    {op}: {len(by_op[op])}  [{sample}{more}]")
    if dep_all_degenerate_rows and max_lines > 0:
        # Visibility into upstream Capstone tagging: canonicals whose
        # every variant has a degenerate access list (1-entry, no dst).
        # The audit classifier promotes them to affirmative
        # dep_all_to_all as a conservative-correct workaround; the
        # underlying tagging is incomplete in Capstone's source
        # tables and worth reporting upstream when patching them up.
        by_op = {}
        for const_name, op in dep_all_degenerate_rows:
            by_op.setdefault(op, []).append(const_name)
        print(f"  upstream-Capstone gap — canonicals with only "
              f"degenerate variants ({len(dep_all_degenerate_rows)}):")
        for op in sorted(by_op, key=lambda k: (-len(by_op[k]), k)):
            sample = ", ".join(by_op[op][:4])
            more = "" if len(by_op[op]) <= 4 else f", ... +{len(by_op[op]) - 4}"
            print(f"    {op}: {len(by_op[op])}  [{sample}{more}]")

    return len(missing) + len(mismatched) + len(stale)


def audit_regs_one(info: IsaInfo, *, max_lines: int) -> int:
    constants = enum_reg_constants(info)
    unmapped: list[str] = []
    ignored: list[str] = []
    mapped = 0
    for const_name in constants:
        entry = classify_reg(info, const_name)
        if entry.ignored:
            ignored.append(const_name)
        elif entry.primary == "REG_NONE":
            unmapped.append(const_name)
        else:
            mapped += 1
    print(f"{info.key} regs: constants={len(constants) + 1} mapped={mapped} ignored={len(ignored)} unmapped={len(unmapped)}")
    if unmapped:
        print("  unmapped stateful registers:")
        for const_name in unmapped[:max_lines]:
            print(f"    {const_name}")
        if len(unmapped) > max_lines:
            print(f"    ... {len(unmapped) - max_lines} more")
    if ignored and max_lines > 0:
        print("  intentionally ignored:")
        for const_name in ignored[:max_lines]:
            print(f"    {const_name}")
        if len(ignored) > max_lines:
            print(f"    ... {len(ignored) - max_lines} more")
    return len(unmapped)


def apply_one(info: IsaInfo) -> None:
    constants = enum_constants(info)
    existing = parse_existing(info)
    text = info.header.read_text()
    new_text = replace_table_body(text, info, generated_body(info, constants, existing))
    info.header.write_text(new_text)


def apply_regs_one(info: IsaInfo) -> None:
    constants = enum_reg_constants(info)
    text = info.header.read_text()
    new_text = replace_reg_table_body(text, info, generated_reg_body(info, constants))
    info.header.write_text(new_text)


# ---------------------------------------------------------------------------
# QEMU-indexed register tables
#
# The table above is keyed on a CAPSTONE register enum value and carries
# a QEMU identity in each row.  That is backwards for everything except
# the one path that arrives holding a Capstone operand: the CONTENT is
# QEMU's -- .qemu_reg names a register in QEMU's GDB-stub namespace, the
# same namespace qemu_plugin_get_registers() hands a plugin -- while the
# KEY is a second decoder's enumeration.
#
# Three things follow from the key, and all three are measurable:
#
#  1. A register QEMU carries but Capstone's enum cannot NAME has no
#     slot at all.  On x86_64 that is 12 registers, mxcsr and the x87
#     control/status file (fctrl, ftag, fop, fioff, fiseg, fooff,
#     foseg) among them -- state the ISA reads and writes, that QEMU
#     holds exactly, and that no dependency edge can reach through this
#     key.  Their generic ID comes from QEMU_ONLY_REG_IDS below instead,
#     because "Capstone has no constant for it" is a fact about the
#     ROUTE and REG_NONE would state it as a fact about the REGISTER.
#  2. Which QEMU register's VALUE is published for a generic ID was
#     decided by CAPSTONE ENUM ORDER: the plugin's reverse index takes
#     "the first singleton row" walking the Capstone-indexed array.
#  3. A Capstone row that disagreed with another row about the same
#     QEMU register would simply win wherever it was consulted.  Keyed
#     on QEMU there is one row per register and the disagreement cannot
#     be expressed.
#
# So these rows invert the index: one row per register in QEMU's
# namespace, sorted by (feature, name), carrying the generic ID.  The
# Capstone-keyed table stays -- it is how a Capstone operand reaches a
# register -- but it becomes a ROUTE to these rows rather than the
# authority for their content, and the plugin cross-checks it against
# them at install.
# ---------------------------------------------------------------------------

QREG_UNNAMED = 0
QREG_ROUTED = 1


@dataclass(frozen=True)
class QemuRegRow:
    feature: str
    name: str
    entry: RegEntry | None
    cap_rows: tuple[str, ...]
    # Non-empty only on a row whose ID came from QEMU_ONLY_REG_IDS: why that
    # role dictates that ID, and whether the register is reachable at all.
    reason: str = ""

    @property
    def tier(self) -> int:
        return QREG_ROUTED if self.cap_rows else QREG_UNNAMED


# ---------------------------------------------------------------------------
# The registers Capstone's enum cannot name, classified from QEMU's side.
#
# A row above gets its generic ID from whichever Capstone register constant
# routes to it.  For a register no Capstone constant names there is no such
# route, and the row was emitted REG_NONE -- which the plugin reads as "this
# register HAS no generic word" and refuses a dependency on.  That is a true
# statement about the ROUTE and a false one about the REGISTER: x86's `fctrl`
# IS the x87 control word and REG_FPCW is exactly the word for it.
#
# So the fold R7.2 ruled for the Capstone-reachable system registers is
# applied here to the unreachable ones, keyed on QEMU's own name.  Existing
# IDs only, chosen by the register's ROLE:
#
#   the FP CONTROL word (rounding, precision, exception masks) -> REG_FPCW
#   the rest of the FP control-and-status file                 -> REG_FCSR
#
# and the split between those two is the one champsim_tracer_generic_ids.h
# already states and measured: every FP instruction READS the control word
# and WRITES the status word, so one ID for both manufactures a
# read-modify-write edge between consecutive unrelated FP instructions.
# MXCSR is named there explicitly as REG_FCSR -- one register that is
# control and status together, which the vocabulary may not split.
#
# `reason` is not decoration.  R8.7 requires an ID claim to show the
# register OBSERVED on a decode rather than merely present in a table, and
# five of these x87 rows CANNOT be observed on any decode: QEMU does not
# model them.  target/i386/gdbstub.c returns a literal 0 for ftag, fiseg,
# fioff, foseg, fooff and fop -- there is no CPUX86State field to write, so
# no TCG operation names one and no provenance bit can ever carry one.  The
# ID is still the right answer to "what IS this register", and the reason
# column is where the row says the answer is unreachable, so a later reader
# does not mistake its presence for a witness.
#
# Rows are keyed (feature, name) in QEMU's GDB-stub namespace, which is the
# same key the table is sorted on.
QEMU_ONLY_REG_IDS: dict[str, dict[tuple[str, str], tuple[str, str]]] = {
    "x86": {
        # The SEGMENT-REGISTER BASES.  QEMU's namespace carries `fs`/`gs` (the
        # selector) and `fs_base`/`gs_base` (the hidden descriptor's base)
        # as separate rows; Capstone's enum has a constant only for the
        # selector, so the base rows were emitted REG_NONE.  That is again a
        # true statement about the ROUTE and a false one about the REGISTER:
        # in 64-bit mode the selector is architecturally inert and the base
        # IS what an FS- or GS-overridden address depends on, so a row saying
        # the base has no generic word makes every `mov %fs:0x28,%rax` read
        # as depending on nothing.  Under the composed-register contract
        # (#277: a folded FIELD publishes its CONTAINER) the base is a member
        # of the segment register, and the container's word is the answer.
        #
        # k_gs_base is deliberately NOT here: MSR_KERNEL_GS_BASE is a
        # different architectural register that swapgs exchanges with GS, not
        # a member of it.
        ("org.gnu.gdb.i386.core", "fs_base"): (
            "REG_SEG3",
            "the FS segment register's hidden base (env->segs[R_FS].base); "
            "OBSERVED via the declared env range -- the address provenance "
            "of every FS-overridden access",
        ),
        ("org.gnu.gdb.i386.core", "gs_base"): (
            "REG_SEG4",
            "the GS segment register's hidden base (env->segs[R_GS].base); "
            "same role as fs_base above",
        ),
        ("org.gnu.gdb.i386.core", "fctrl"): (
            "REG_FPCW",
            "x87 control word (env->fpuc); OBSERVED via the declared env "
            "range -- fnstcw's store-data provenance",
        ),
        ("org.gnu.gdb.i386.core", "mxcsr"): (
            "REG_FCSR",
            "SSE control AND status in one register (env->mxcsr); "
            "generic_ids.h names it REG_FCSR explicitly",
        ),
        ("org.gnu.gdb.i386.core", "ftag"): (
            "REG_FCSR",
            "x87 tag word: status.  UNREACHABLE -- QEMU keeps the unpacked "
            "env->fptags[8] and gdbstub.c returns 0 for the packed word",
        ),
        ("org.gnu.gdb.i386.core", "fop"): (
            "REG_FCSR",
            "x87 last-opcode, part of the saved FP environment.  "
            "UNREACHABLE -- gdbstub.c returns 0; QEMU has no field",
        ),
        ("org.gnu.gdb.i386.core", "fioff"): (
            "REG_FCSR",
            "x87 last-instruction offset, saved FP environment.  "
            "UNREACHABLE -- gdbstub.c returns 0; QEMU has no field",
        ),
        ("org.gnu.gdb.i386.core", "fiseg"): (
            "REG_FCSR",
            "x87 last-instruction selector, saved FP environment.  "
            "UNREACHABLE -- gdbstub.c returns 0; QEMU has no field",
        ),
        ("org.gnu.gdb.i386.core", "fooff"): (
            "REG_FCSR",
            "x87 last-data offset, saved FP environment.  "
            "UNREACHABLE -- gdbstub.c returns 0; QEMU has no field",
        ),
        ("org.gnu.gdb.i386.core", "foseg"): (
            "REG_FCSR",
            "x87 last-data selector, saved FP environment.  "
            "UNREACHABLE -- gdbstub.c returns 0; QEMU has no field",
        ),
    },
}


def qemu_only_reg_entry(info: IsaInfo,
                        key: QemuRegKey) -> tuple[RegEntry | None, str]:
    """The role-dictated ID for a register no Capstone constant names."""
    row = QEMU_ONLY_REG_IDS.get(info.key, {}).get((key.feature, key.name))
    if row is None:
        return None, ""
    return RegEntry(row[0]), row[1]


def qemu_reg_rows(info: IsaInfo) -> tuple[list[QemuRegRow], list[str]]:
    """One row per QEMU register, plus the conflicts found building them.

    A conflict is two Capstone rows naming the same QEMU register with
    different generic content.  It is returned rather than raised so the
    census can print every one; --apply refuses on a non-empty list,
    because a table that cannot decide what a register IS must not be
    emitted as though it had.
    """
    namespace = QEMU_REG_KEYS[info.key]()
    by_key: dict[QemuRegKey, list[tuple[str, RegEntry]]] = {}
    orphans: list[str] = []
    known = set(namespace.values())
    for const_name in enum_reg_constants(info):
        entry = classify_reg(info, const_name)
        if entry.ignored:
            continue
        key = qemu_reg_key(info, const_name)
        if key is None:
            continue
        if key not in known:
            # A Capstone row pointing at a register QEMU's namespace does
            # not contain.  Reading it yields a null handle and a width-0
            # field, so it is a defect, not a rounding error.
            orphans.append(f"{const_name} -> {key.feature}:{key.name} "
                           f"(not in QEMU's namespace)")
            continue
        by_key.setdefault(key, []).append((const_name, entry))

    conflicts: list[str] = list(orphans)
    rows: list[QemuRegRow] = []
    qemu_only = dict(QEMU_ONLY_REG_IDS.get(info.key, {}))
    for key in sorted(known, key=lambda k: (k.feature, k.name)):
        routed = by_key.get(key, [])
        entry = None
        reason = ""
        if routed:
            distinct = {e for _, e in routed}
            if len(distinct) > 1:
                conflicts.append(
                    f"{key.feature}:{key.name} claimed differently by "
                    + ", ".join(f"{c}={e.primary}"
                                + (f"+{list(e.aliases)}" if e.aliases else "")
                                for c, e in sorted(routed)))
            entry = routed[0][1]
            if (key.feature, key.name) in qemu_only:
                # A rule for a register a Capstone constant DOES reach is a
                # second opinion about the same row, which is the exact
                # disagreement keying on QEMU was meant to make impossible.
                conflicts.append(
                    f"{key.feature}:{key.name} has a QEMU_ONLY_REG_IDS rule "
                    f"but is reachable from {len(routed)} Capstone row(s)")
        else:
            entry, reason = qemu_only_reg_entry(info, key)
        qemu_only.pop((key.feature, key.name), None)
        rows.append(QemuRegRow(key.feature, key.name, entry,
                               tuple(sorted(c for c, _ in routed)), reason))
    # A rule naming no register in the namespace is dead: it can never fire,
    # and a dead rule that reads as coverage is how an allowlist lies.
    for feature, name in sorted(qemu_only):
        conflicts.append(f"{feature}:{name} has a QEMU_ONLY_REG_IDS rule but "
                         f"is not in QEMU's namespace")
    return rows, conflicts


def format_qemu_reg_row(row: QemuRegRow) -> str:
    tier = "QREG_ROUTED" if row.tier == QREG_ROUTED else "QREG_UNNAMED"
    if row.entry is None:
        body = ".reg_id = REG_NONE"
    elif row.entry.aliases:
        body = (f".reg_id = {row.entry.primary}, "
                f".n_regs = {len(row.entry.aliases)}, "
                f".regs = {{ {', '.join(row.entry.aliases)} }}")
    else:
        body = f".reg_id = {row.entry.primary}"
    if row.entry is not None and row.entry.is_int_flags:
        body += ", .is_int_flags = true"
    if row.cap_rows:
        comment = (f"  /* {len(row.cap_rows)} capstone row"
                   f"{'' if len(row.cap_rows) == 1 else 's'} */")
    elif row.reason:
        comment = f"  /* {row.reason} */"
    else:
        comment = ""
    return (f"    {{ .feature = {c_string(row.feature)}, "
            f".name = {c_string(row.name)}, "
            f"{body}, .cap_rows = {len(row.cap_rows)}, "
            f".tier = {tier} }},{comment}")


def qemu_regs_header_text(info: IsaInfo, rows: list[QemuRegRow]) -> str:
    guard = f"CHAMPSIM_TRACER_QEMU_REGS_{info.key.upper()}_H"
    routed = sum(1 for r in rows if r.tier == QREG_ROUTED)
    classified = sum(1 for r in rows if r.entry is not None)
    lines = [
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "/*",
        f" * QEMU-indexed register table for {info.key} -- auto-generated by",
        f" * {Path(__file__).name} --qemu-regs.  Do not hand-edit a row.",
        " *",
        " * One row per register in QEMU's GDB-stub namespace -- the",
        " * namespace qemu_plugin_get_registers() reports -- sorted by",
        " * (feature, name) so a consumer can bisect.  This is the",
        " * authority for what generic dependency slot a register is;",
        " * the Capstone-keyed table is a route to these rows and is",
        " * cross-checked against them at install.",
        " *",
        " * .tier says whether the Capstone key can reach the row:",
        " *   QREG_ROUTED   at least one Capstone register id maps here",
        " *   QREG_UNNAMED  QEMU carries the register and Capstone's enum",
        " *                 has no id for it, so no Capstone-fed operand",
        " *                 can ever name it.  These rows are reachable",
        " *                 only by QEMU identity.",
        " *",
        " * SPDX-License-Identifier: GPL-2.0-or-later",
        " * Author: Maccoy Merrell",
        " */",
        "",
        f"/* {info.key}: {len(rows)} QEMU registers, {routed} reachable from",
        f" * Capstone, {len(rows) - routed} reachable only by QEMU identity,",
        f" * {classified} carrying a generic id. */",
        f"static const QemuRegRow qemu_regs_{info.key}[] = {{",
    ]
    lines.extend(format_qemu_reg_row(row) for row in rows)
    lines.append("};")
    lines.append("")
    lines.append(f"static const size_t qemu_regs_{info.key}_count =")
    lines.append(f"    sizeof(qemu_regs_{info.key}) / "
                 f"sizeof(qemu_regs_{info.key}[0]);")
    lines.append("")
    lines.append(f"#endif /* {guard} */")
    return "\n".join(lines) + "\n"


def qemu_regs_census(info: IsaInfo, rows: list[QemuRegRow],
                     conflicts: list[str], max_lines: int = 40) -> int:
    routed = [r for r in rows if r.tier == QREG_ROUTED]
    unnamed = [r for r in rows if r.tier == QREG_UNNAMED]
    print(f"===== {info.key}: QEMU-indexed registers =====")
    print(f"QEMU namespace: {len(rows)} registers")
    print(f"  reachable from a Capstone operand: {len(routed)}")
    print(f"  reachable ONLY by QEMU identity:   {len(unnamed)}")
    for row in unnamed[:max_lines]:
        print(f"      {row.feature}:{row.name}")
    if len(unnamed) > max_lines:
        print(f"      ... {len(unnamed) - max_lines} more")
    fanin = sorted(routed, key=lambda r: -len(r.cap_rows))[:5]
    print("  widest Capstone fan-in: "
          + ", ".join(f"{r.name}={len(r.cap_rows)}" for r in fanin))
    print(f"CONFLICTS (a register two Capstone rows describe differently, "
          f"or a row naming no QEMU register): {len(conflicts)}")
    for line in conflicts[:max_lines]:
        print(f"    {line}")
    return len(conflicts)


def apply_qemu_regs_one(info: IsaInfo) -> int:
    rows, conflicts = qemu_reg_rows(info)
    if conflicts:
        print(f"{info.key}: REFUSING to write -- {len(conflicts)} conflicts")
        for line in conflicts:
            print(f"    {line}")
        return len(conflicts)
    out = PLUGIN_DIR / f"champsim_tracer_qemu_regs_{info.key}.h"
    out.write_text(qemu_regs_header_text(info, rows))
    print(f"wrote {out}")
    return 0


# ---------------------------------------------------------------------------
# QEMU decode identity (decodetree targets)
#
# The rows above are keyed on a Capstone instruction id: what a
# DISASSEMBLER says about the bytes.  The rows below are keyed on what
# QEMU itself dispatched on -- the decodetree pattern that matched, i.e.
# the trans_<name>() the translator called.  See
# include/qemu/qemu-plugin.h (qemu_plugin_insn_decode_id) for the
# exported contract and
# cst_runs/p3/arc3/DECODE_IDENTITY_CONTRACT.md for the cross-target one.
#
# The universe of identities is read out of the GENERATED decoders in a
# build directory rather than re-derived from the .decode sources here.
# Re-deriving would mean reimplementing decodetree's name qualification
# and its FNV-1a, and a second implementation of an identifier is a
# second identifier.  The generated table is what QEMU compiled.
# ---------------------------------------------------------------------------

# ISA key -> the linux-user target whose generated decoders define that
# ISA's identity universe.  x86 is absent on purpose: i386 does not use
# decodetree, and its identity comes from the X86_OP_ENTRY table instead.
QEMU_IDENT_TARGETS: dict[str, str] = {
    "aarch64": "aarch64-linux-user",
    "riscv": "riscv64-linux-user",
    "mips": "mipsel-linux-user",
}

# i386 is not a decodetree target and has no generated decoder to read.
# Its identity universe is the SOURCE table QEMU dispatches on, and the
# id is the source line of the macro expansion, so the universe is read
# from the source file rather than from the build tree.
QEMU_IDENT_SOURCE_TABLES: dict[str, str] = {
    "x86": "target/i386/tcg/decode-new.c.inc",
}

# i386's decode table is not the whole of its identity universe.  The
# eight escape rows 0xD8..0xDF all name `x87` and gen_x87() then dispatches
# on the modrm byte internally, so those eight ids answer for the whole
# x87 instruction set and one of them names an operation for every other
# instruction under its escape byte too.
# scripts/x86_x87_ident_instrument.py states the finer identity in the
# source, one row per dispatch leaf, in the same row format the MIPS
# hand-written table uses.  Reading only decode-new.c.inc here would
# report those leaves as absent -- the census would say the escape rules
# are unqualified and the split unresolved, which is a zero produced by
# not looking.
X86_IDENT_QUALIFIED = "target/i386/tcg/x87_ident.c.inc"

# The emitter fact for a qualified leaf.  It is NOT an X86_OP_* macro
# suffix: the leaf is a case label inside gen_x87, not a table row, so
# there is no operand template to read and x86_emitter_refuses() must not
# read one.  Naming the kind rather than borrowing the escape row's is
# what keeps that honest.
X86_QUALIFIED_KIND = "x87leaf"

# One X86_OP_* macro site.  Group 1 is the macro suffix (the emitter
# fact), group 2 the first argument, group 3 the second -- for the
# three-operand forms that is op0_, the DESTINATION template, and it is
# spelled `None` on a row that produces no destination.
X86_SLOT_RE = re.compile(
    r'\bX86_OP_(ENTRY[0-4rw]{0,2}|GROUP[0-3rw]{0,2}|LEAF|SET_GEN)'
    r'\s*\(\s*([A-Za-z0-9_]+)\s*(?:,\s*([A-Za-z0-9_]+))?')

# Macro forms whose expansion sets op0 = None unconditionally, i.e. the
# row states that QEMU computes a value and writes it nowhere.  This is
# the emitter fact that separates `cmp` from `sub`: both dispatch to
# gen_SUB and both are NAMED SUB, and only the operand template says
# which one the row is.  X86_OP_ENTRY3 / ENTRY4 / GROUP3 take op0_ as an
# argument instead, so they are decided per site from group 3.
X86_NO_DEST_KINDS = frozenset(("ENTRYrr", "ENTRYr", "ENTRY0", "GROUP0"))
X86_OP0_ARG_KINDS = frozenset(("ENTRY3", "ENTRY4", "GROUP3"))

# Decoders a target has that decodetree does not generate.  Their identity
# tables are in the source tree, in the same row format.
QEMU_IDENT_HANDWRITTEN = {
    "mips": ["target/mips/tcg/translate_ident.c.inc"],
}

IDENT_ROW_RE = re.compile(
    r'^\s*\{\s*(0x[0-9a-f]+)u,\s*"([^"]+)"\s*\},\s*/\*\s*(\S+):(\d+)\s*\*/')

# The same row with its provenance on the line ABOVE.  An ENCODING-QUALIFIED
# identity carries its 32 fixed bits in the name, and the row plus a trailing
# `/* file:line */` does not fit 80 columns, so the generator lifts the
# comment.  Reading only the one-line form would make those rows INVISIBLE to
# the universe -- the census would report the rule unqualified and the split
# unresolved, which is a zero produced by not looking.
IDENT_ROW_BARE_RE = re.compile(
    r'^\s*\{\s*(0x[0-9a-f]+)u,\s*"([^"]+)"\s*\},\s*$')
IDENT_PROV_RE = re.compile(r'^\s*/\*\s*(\S+):(\d+)\s*\*/\s*$')


@dataclass(frozen=True)
class QemuIdent:
    ident: int
    name: str            # "disas_a64/ADD_i" -- decoder-qualified
    src_file: str
    src_line: int
    # The EMITTER FACT, where the target's decode table carries one.  On
    # i386 this is the X86_OP_* macro the row was written with, and the
    # macro states the row's operand template: X86_OP_ENTRYrr expands to
    # op0 = None, i.e. QEMU computes the result and throws it away.  That
    # is how `cmp` is spelled through a slot named SUB, and it is the only
    # thing in the table that says so.  decodetree targets carry
    # "decodetree" -- their pattern name is the identity and there is no
    # second fact to read.
    kind: str = "decodetree"

    @property
    def decoder(self) -> str:
        """The decode function the rule lives in.

        decodetree qualifies every pattern with it (`disas_a64/ADD_i`);
        i386's table is one file and its rows carry a bare generator
        name, so the whole table is one decoder and says so.
        """
        if "/" not in self.name:
            return "decode-new"
        return self.name.split("/", 1)[0]

    @property
    def pattern(self) -> str:
        """The rule's own trans_ name, unqualified.

        Both qualifications are stripped: the decode function in front,
        and the pattern's own fixed bits behind.  decodetree appends the
        bits wherever one trans_ function is reached from several
        patterns -- riscv reaches trans_addi() from C.ADDI4SPN, C.ADDI,
        C.LI, C.ADDI16SP and C.MV -- so the rows are distinct rules with
        distinct ids while still naming the same QEMU function, and it is
        that function name a Capstone mnemonic is matched against.
        """
        name = self.name if "/" not in self.name else self.name.split("/", 1)[1]
        return name.split("@", 1)[0]

    @property
    def bits(self) -> str:
        """The pattern's own fixed bits, or "" where the rule is the only
        one reaching its trans_ function and needed no disambiguation."""
        _, sep, bits = self.name.partition("@")
        return bits if sep else ""


def parse_x86_identities() -> list[QemuIdent]:
    """Read i386's identity universe out of the decode table's SOURCE.

    The i386 id IS the source line of the X86_OP_* expansion, so the
    universe and the ids both come from the same scan, and the scan is
    the only place the EMITTER FACT is visible: the macro suffix and,
    for the three-operand forms, the op0_ argument.  Neither survives
    into the build tree.

    Fails loudly on a line carrying two slots, because that is the one
    property the derivation depends on -- two rows on one line are one
    id, and the export would be merging two decode rules silently.
    """
    path = ROOT / QEMU_IDENT_SOURCE_TABLES["x86"]
    if not path.is_file():
        raise SystemExit(f"{path} does not exist -- no i386 decode table to read")
    rows: list[QemuIdent] = []
    in_define = False
    rel = str(path.relative_to(ROOT))
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        cont = line.endswith("\\")
        # The macro DEFINITIONS expand X86_OP_ENTRY3 inside themselves;
        # counting those would mint slots no row ever carries.
        if line.lstrip().startswith("#define"):
            in_define = cont
            continue
        if in_define:
            in_define = cont
            continue
        for m in X86_SLOT_RE.finditer(line):
            kind = m.group(1)
            # X86_OP_SET_GEN(entry_, op) names the entry first and the
            # generator second; every other form names the op first.
            name = m.group(3) if kind == "SET_GEN" else m.group(2)
            if kind in X86_OP0_ARG_KINDS and m.group(3) == "None":
                kind = kind + "/noDest"
            rows.append(QemuIdent(lineno, name, rel, lineno, kind))
    if not rows:
        raise SystemExit(
            f"{path}: no X86_OP_* sites matched -- the scanner does not fit "
            f"this source, and reporting an empty universe would read as "
            f"'i386 has no decode identity' when the truth is 'nothing "
            f"was measured'")
    by_line: dict[int, list[str]] = {}
    for r in rows:
        by_line.setdefault(r.ident, []).append(r.name)
    clashes = {k: v for k, v in by_line.items() if len(v) > 1}
    if clashes:
        for k, v in sorted(clashes.items()):
            print(f"  SLOT COLLISION line {k}: {', '.join(v)}")
        raise SystemExit(
            f"x86: {len(clashes)} source lines carry more than one slot -- "
            f"the exported id cannot tell them apart")
    qualified = parse_x86_qualified_identities()
    slots = {r.ident for r in rows}
    collide = [q for q in qualified if q.ident in slots]
    if collide:
        for q in collide:
            print(f"  ID COLLISION 0x{q.ident:08x}: {q.name} vs the "
                  f"decode-new.c.inc slot at that id")
        raise SystemExit(
            f"x86: {len(collide)} qualified identity hash(es) collide with a "
            f"__LINE__ slot -- two rules sharing one id merge silently in "
            f"every consumer")
    return rows + qualified


def parse_x86_qualified_identities() -> list[QemuIdent]:
    """The ENCODING-QUALIFIED leaves of gen_x87's internal dispatch.

    Same row format as the MIPS hand-written table: the provenance comment
    is LIFTED above the row, because a 51-character identity plus a
    trailing `/* file:line */` does not fit 80 columns.  Reading only the
    one-line form would make every leaf invisible.

    Fails loudly on an empty or absent table.  A missing file and 'the x87
    space has no internal dispatch' are indistinguishable in a count, and
    only one of them is a fact about QEMU.
    """
    path = ROOT / X86_IDENT_QUALIFIED
    if not path.is_file():
        raise SystemExit(
            f"{path} does not exist -- run "
            f"scripts/x86_x87_ident_instrument.py.  Without it the x87 "
            f"escape rows report as unqualified, which is not what the "
            f"source says.")
    rows: list[QemuIdent] = []
    prov: tuple[str, int] | None = None
    for line in path.read_text().splitlines():
        m = IDENT_PROV_RE.match(line)
        if m:
            prov = (m.group(1), int(m.group(2)))
            continue
        m = IDENT_ROW_BARE_RE.match(line)
        if m and prov is not None:
            rows.append(QemuIdent(int(m.group(1), 16), m.group(2),
                                  prov[0], prov[1], X86_QUALIFIED_KIND))
        prov = None
    if not rows:
        raise SystemExit(
            f"{path}: no identity rows matched -- the reader does not fit "
            f"this table, and reporting an empty universe would read as "
            f"'gen_x87 has no internal dispatch'")
    return rows


def qemu_ident_universe(build_dir: Path | None, isa: str) -> list[QemuIdent]:
    """The identity universe for one target, from wherever it lives."""
    if isa in QEMU_IDENT_SOURCE_TABLES:
        return parse_x86_identities()
    if build_dir is None:
        raise SystemExit(f"{isa}: a decodetree target needs --build-dir")
    return parse_qemu_identities(build_dir, isa)


def parse_qemu_identities(build_dir: Path, isa: str) -> list[QemuIdent]:
    """Read the identity universe out of one target's generated decoders.

    Fails loudly rather than reporting a small number: a missing build
    directory and an ISA with no identities are indistinguishable in a
    count, and only one of them is a fact about QEMU.
    """
    target = QEMU_IDENT_TARGETS.get(isa)
    if target is None:
        raise SystemExit(f"{isa}: not a decodetree target, no QEMU identity universe")
    apdir = build_dir / f"libqemu-{target}.a.p"
    if not apdir.is_dir():
        raise SystemExit(f"{apdir} does not exist -- build {target} first")
    files = sorted(apdir.glob("decode-*.c.inc"))
    if not files:
        raise SystemExit(f"no generated decoders under {apdir}")
    # A target's identity universe is not always all decodetree.  The MIPS
    # base ISA is a hand-written switch, and scripts/mips_ident_instrument.py
    # emits its rows into the SOURCE tree rather than the build tree,
    # because the thing it instruments is source.  Reading only the
    # generated decoders here would report that universe as absent, which
    # is the exact shape of wrong answer this function exists to refuse.
    handwritten = QEMU_IDENT_HANDWRITTEN.get(isa, [])
    extra: list[Path] = []
    for rel in handwritten:
        path = ROOT / rel
        if not path.is_file():
            raise SystemExit(
                f"{path} is missing -- {isa} has a hand-written decoder whose "
                f"identity table has not been generated; run "
                f"scripts/mips_ident_instrument.py")
        extra.append(path)
    rows: list[QemuIdent] = []
    for path in files + extra:
        prov = None
        for line in path.read_text().splitlines():
            m = IDENT_ROW_RE.match(line)
            if m:
                rows.append(QemuIdent(int(m.group(1), 16), m.group(2),
                                      m.group(3), int(m.group(4))))
                prov = None
                continue
            m = IDENT_PROV_RE.match(line)
            if m:
                prov = (m.group(1), int(m.group(2)))
                continue
            m = IDENT_ROW_BARE_RE.match(line)
            if m:
                if prov is None:
                    raise SystemExit(
                        f"{path}: identity row {m.group(2)!r} carries no "
                        f"provenance, on its own line or the one above -- a "
                        f"row with no source is not a rule this generator "
                        f"will admit")
                rows.append(QemuIdent(int(m.group(1), 16), m.group(2),
                                      prov[0], prov[1]))
                prov = None
                continue
            prov = None
    if not rows:
        raise SystemExit(
            f"{apdir}: decoders carry no identity rows -- the tree was built "
            f"with the export disabled, so any census here would read as "
            f"'no identity exists' when the truth is 'nothing was measured'")
    # decodetree checks for hash collisions WITHIN one .decode file; it
    # cannot check across files because each is a separate invocation.
    # The uniqueness the plugin API promises is per TARGET, so it has to
    # be checked here, where the whole target is in view.
    by_id: dict[int, list[str]] = {}
    for r in rows:
        by_id.setdefault(r.ident, []).append(r.name)
    clashes = {k: v for k, v in by_id.items() if len(set(v)) > 1}
    if clashes:
        for k, v in sorted(clashes.items()):
            print(f"  IDENT COLLISION 0x{k:08x}: {', '.join(sorted(set(v)))}")
        raise SystemExit(
            f"{isa}: {len(clashes)} cross-decoder identity collisions -- "
            f"two different decode rules share one id, which breaks the "
            f"uniqueness qemu_plugin_insn_decode_id() promises")
    return rows


# idprobe TSVs are named for the QEMU TARGET they came from, and the ids
# inside are explicitly not comparable across targets.  Joining an
# aarch64 TSV against the riscv universe would not fail -- it would
# silently score one target's ids as another's residue -- so the routing
# is by name and a file that names no target is refused rather than
# guessed at.
OBSERVED_ISA_TOKENS = {
    "x86": ("x86", "i386"),
    "aarch64": ("aarch64", "arm64"),
    "riscv": ("riscv",),
    "mips": ("mips",),
}


def _observed_matches_isa(path: Path, isa: str) -> bool:
    stem = path.name.lower()
    if not any(tok in stem for group in OBSERVED_ISA_TOKENS.values()
               for tok in group):
        raise SystemExit(
            f"{path}: names no target, so which identity universe its ids "
            f"belong to is a guess -- rename it to carry the target")
    return any(tok in stem for tok in OBSERVED_ISA_TOKENS[isa])


def enum_value_map(info: IsaInfo) -> dict[int, str]:
    """Capstone insn-enum VALUE -> constant name.

    The generated tables are designated arrays indexed by the enum
    value, so the value is the key an observed decode arrives under.
    Deriving it as "position in declaration order, INVALID = 0" is only
    sound while the enum is dense, so that is CHECKED here rather than
    assumed: an explicit initialiser anywhere in the instruction enum
    would shift every constant after it and silently re-label the whole
    observed set.
    """
    text = info.capstone_header.read_text()
    start = text.index(info.prefix + "INVALID")
    end = text.index(info.prefix + "ENDING", start)
    body = text[start:end]
    explicit = re.findall(re.escape(info.prefix) + r"[A-Z0-9_]+\s*=", body)
    # INVALID = 0 is the one initialiser the derivation depends on.
    explicit = [e for e in explicit if "INVALID" not in e]
    if explicit:
        raise SystemExit(
            f"{info.capstone_header}: the {info.prefix}* enum carries "
            f"explicit values ({', '.join(explicit[:4])}) -- position is no "
            f"longer the value and every observed decode would be joined to "
            f"the wrong row")
    return {i + 1: c for i, c in enumerate(enum_constants(info))}


def load_observed(paths: list[Path]) -> dict[int, dict[str, object]]:
    """Fold idprobe TSV records into id -> {name, caps, mnem}.

    An idprobe record is one OBSERVED decode: QEMU translated those
    bytes, named the rule it used, and -- since the probe was extended
    for this join -- reported the CAPSTONE ENUM VALUE the same bytes
    decode to.  The enum value is what the classification tables are
    indexed by, so the join is exact.

    The disassembly TEXT is kept for the census to print and for
    nothing else.  It is not a key: QEMU prints x86 in AT&T syntax with
    the operand size spelled into the mnemonic, so `cmpq` and `testb`
    match no Capstone constant at all while `movq` matches the WRONG
    one.  A six-field record is therefore required; a five-field one is
    the older probe and is refused rather than joined on text.
    """
    import collections
    obs: dict[int, dict[str, object]] = {}
    total = 0
    for p in paths:
        for lineno, line in enumerate(Path(p).read_text().splitlines(), 1):
            f = line.split("\t")
            if len(f) < 5:
                continue
            # The record is parsed from BOTH ENDS, never by field index
            # past the disassembly: a target's disassembly may itself
            # contain tabs -- MIPS prints "move\tt9,ra" -- so field 5
            # is the operand list there and not the Capstone id.  The
            # id is the LAST field by construction.
            if len(f) < 6:
                raise SystemExit(
                    f"{p}:{lineno}: five-field record -- this is the probe "
                    f"from before the Capstone id was added, and joining it "
                    f"would have to go through the disassembly text, which "
                    f"is not a key.  Re-run idprobe.")
            ident = int(f[1])
            cap = int(f[-1])
            disas = "\t".join(f[4:-1])
            text = disas.split()[0] if disas.strip() else "?"
            e = obs.setdefault(ident, {"name": f[2] if ident else "-",
                                       "caps": collections.Counter(),
                                       "mnem": collections.Counter()})
            e["caps"][cap] += 1
            e["mnem"][text] += 1
            total += 1
    if total == 0:
        raise SystemExit("no idprobe records read -- refusing to census nothing")
    return obs


def load_pairs(paths: list[Path]) -> dict[int, dict[str, object]]:
    """Fold PAIR-CENSUS files into the same shape load_observed returns.

    The pair census is written by the tracer itself
    (CST_QEMU_IDENT_PAIRS=<path>) and carries exactly the join this
    generator needs: (QEMU decode id, QEMU decode name, Capstone insn
    id, count).  It is preferred over an idprobe TSV on every target
    and REQUIRED on riscv64 and mipsel, where a standalone plugin's
    qemu_plugin_insn_detail() reports insn_id 0 for every instruction --
    QEMU enables its own Capstone for x86 and arm and not for those two,
    so a probe written that way measures nothing and says so as a zero.

    It carries no disassembly text, and does not need to: the text was
    never the key.
    """
    import collections
    obs: dict[int, dict[str, object]] = {}
    total = 0
    for path in paths:
        for lineno, line in enumerate(Path(path).read_text().splitlines(), 1):
            if line.startswith("#") or not line.strip():
                continue
            f = line.split("\t")
            if len(f) != 4:
                raise SystemExit(
                    f"{path}:{lineno}: expected 4 fields, got {len(f)} -- "
                    f"this is not a pair census")
            ident, name, cap, count = int(f[0]), f[1], int(f[2]), int(f[3])
            e = obs.setdefault(ident, {"name": name,
                                       "caps": collections.Counter(),
                                       "mnem": collections.Counter()})
            e["caps"][cap] += count
            total += count
    if total == 0:
        raise SystemExit("no pair records read -- refusing to census nothing")
    return obs


def _norm_mnemonic(text: str) -> str:
    """Fold the two spellings of one mnemonic onto a single key.

    A Capstone CONSTANT cannot contain a dot, so the riscv extension
    separator is spelled `_` there (RISCV_INS_FMADD_D) and `.` in the
    disassembly (fmadd.d).  Joining on the raw text silently misses
    every dotted riscv mnemonic and reports the miss as "QEMU has no
    identity for this", which is the opposite of what is true.
    """
    return text.lower().replace(".", "_")


def _mnemonic_to_const(info: IsaInfo) -> dict[str, str]:
    """mnemonic text -> Capstone constant, for the rows the tables key on."""
    out: dict[str, str] = {}
    for const in enum_constants(info):
        out.setdefault(_norm_mnemonic(c_mnemonic(const, info.prefix)), const)
    return out


# Provenance tiers for a QEMU-identity row.  They are kept apart because
# they are different strengths of evidence and collapsing them would let
# a name that merely LOOKS like a mnemonic pass for a decode that was
# actually seen.
QID_OBSERVED = "QID_OBSERVED"        # QEMU decoded it; mnemonic seen with it
QID_NAME_MATCHED = "QID_NAME_MATCHED"  # pattern name matches a Capstone
                                       # mnemonic, but no decode observed
QID_NONE = "QID_NONE"                  # neither
QID_SPLIT = "QID_SPLIT"                # observed, and the observations
                                       # DISAGREE: this identity does not
                                       # determine the classification
QID_ADJUDICATED = "QID_ADJUDICATED"     # the observations disagreed and
                                        # QEMU's own decode-table row settles
                                        # which of them describes the rule


# ---------------------------------------------------------------------------
# QID_ADJUDICATED: the split rows QEMU's own table row decides
# ---------------------------------------------------------------------------
#
# A QID_SPLIT row means several Capstone constants were observed decoding
# through ONE QEMU rule and the classifier gives them different answers.
# That is not always a question QEMU declines to answer.  Sometimes QEMU's
# decode-table row REFUTES one of the candidates outright -- it states, in
# the emulator's own source, what the rule is -- and then the row does
# determine the classification and it is only the Capstone key that could
# not express it.
#
# Every entry here is one such row.  The key is (isa, slot id); `winner` is
# the Capstone constant whose payload describes what QEMU's rule does, and
# it MUST be one of the constants actually observed through the rule -- the
# generator refuses otherwise, so an adjudication cannot outlive the
# evidence it was written against.  `why` is the QEMU source fact, and it is
# emitted into the generated header beside the row.
#
# THE BAR FOR AN ENTRY, and it is deliberately narrow.  A candidate may be
# adjudicated away only when the QEMU row REFUTES it (it is wrong about what
# the instruction is) or strictly SUBSUMES it (same classification, one side
# merely less precise).  Two equally valid names for one operation are NOT
# adjudicable here: that is a taxonomy ruling about our own generic opcode
# space, not a fact QEMU states, and a row in that shape stays QID_SPLIT
# with its candidates named.  See docs and the ARC 3 verdict for the rows
# left open on exactly that ground.
QID_ADJUDICATIONS: dict[tuple[str, int], tuple[str, str]] = {
    # 0x6ca = decode-new.c.inc:1738
    #   [0xA5] = X86_OP_ENTRYrr(MOVS, Y,v, X,v)
    # Opcode 0xA5 with the Y/X string-operand pair is the STRING MOVE, at
    # operand size v.  Capstone's X86_INS_MOVSD covers two unrelated
    # instructions -- this one and the SSE scalar-double move -- and its
    # row carries the SSE one, so `rep movsl` was published as a
    # lane-parallel FP vector move.  QEMU decodes the SSE movsd through
    # VMOVSD_ld / VMOVLPx_st, which are different slots entirely; nothing
    # about this rule is FP and nothing about it is lane-parallel.  The
    # surviving candidate is the same string move at the other operand
    # size, which is what the rule is.
    ("x86", 0x6ca): ("X86_INS_MOVSQ",
                     "decode-new.c.inc:1738 [0xA5] X86_OP_ENTRYrr(MOVS, Y,v, "
                     "X,v) -- the string move; the SSE scalar-double move "
                     "decodes through VMOVSD_ld/VMOVLPx_st, not here"),

    # 0x54b = decode-new.c.inc:1355
    #   [0x1e] = X86_OP_ENTRY1(NOP, nop,v)   /* reserved NOP */
    # op0 has type `nop` and gen_NOP is #define'd to gen_MOV, so the row
    # generates no architectural write at all: QEMU executes every 0F 1E
    # encoding as a nop.  That is also what the architecture says with
    # shadow stacks disabled, which they are on this CPU model -- RDSSPD/
    # RDSSPQ is defined to be a NOP when CET_SS is off.  Capstone's
    # X86_INS_RDSSPQ row names a destination write that neither QEMU nor
    # the machine performs.
    ("x86", 0x54b): ("X86_INS_ENDBR64",
                     "decode-new.c.inc:1355 [0x1e] X86_OP_ENTRY1(NOP, nop,v) "
                     "-- op0 type `nop`, gen_NOP = gen_MOV writes nothing; "
                     "rdsspq is architecturally a NOP with CET_SS off"),

    # 0x1ee / 0x1ef / 0x234 = decode-new.c.inc:494 / 495 / 564
    #   X86_OP_ENTRY3(MOVDQ, V,x, None,None, W,x, vex1)       movdqa
    #   X86_OP_ENTRY3(MOVDQ, V,x, None,None, W,x, vex4_unal)  movdqu
    #   X86_OP_ENTRY3(MOVDQ, W,x, None,None, V,x, vex4_unal)  movdqu store
    # The `vexN` class marks a row valid under BOTH the legacy and the VEX
    # encoding, so one rule covers movdqa/vmovdqa (resp. movdqu/vmovdqu).
    # The two candidates agree on everything the wire carries -- same
    # opcode, same lane pair -- and differ only in whether .dep_refine is
    # dep_passthrough or absent.  Absent is the all-inputs default; present
    # is the same answer stated precisely, and it is the shape the rule
    # has: one whole-vector value in, one out.  dep_passthrough bails by
    # itself on any runtime shape outside that group, so adopting it can
    # narrow a mask and cannot invent an edge.
    ("x86", 0x1ee): ("X86_INS_MOVDQA",
                     "decode-new.c.inc:494 X86_OP_ENTRY3(MOVDQ, V,x, "
                     "None,None, W,x, vex1) -- one rule for the legacy and "
                     "VEX spellings; the candidates differ only in whether "
                     "the pass-through refiner is stated"),
    ("x86", 0x1ef): ("X86_INS_MOVDQU",
                     "decode-new.c.inc:495 X86_OP_ENTRY3(MOVDQ, V,x, "
                     "None,None, W,x, vex4_unal) -- as 0x1ee, unaligned"),
    ("x86", 0x234): ("X86_INS_MOVDQU",
                     "decode-new.c.inc:564 X86_OP_ENTRY3(MOVDQ, W,x, "
                     "None,None, V,x, vex4_unal) -- as 0x1ef, store "
                     "direction"),

    # decode_insn32/ori (0x8046d85c) IS NOT ADJUDICATED, and the reason is
    # a measurement, because it looks adjudicable and is not.
    #
    # QEMU's decode file appears to settle it outright.  insn32.decode:153,
    # the line directly above the ori pattern, says in words:
    #
    #   # cbo.prefetch_{i,r,m} instructions are ori with rd=x0 and not
    #   # decoded.
    #
    # There is no prefetch row anywhere in riscv's decode tables, so on the
    # letter of "what rule did the emulator dispatch on" the answer is ori
    # and the GEN_OP_PREFETCH candidate is refuted.  That adjudication was
    # WRITTEN, APPLIED and MEASURED, and the wire's own acceptance caught
    # it: the validator coverage cell reports
    #
    #   opcode_assertion: blk_34 (probe_riscv_prefetch): expected a
    #   PREFETCH instruction in its template insns but saw only
    #   ['BRANCH', 'OR']
    #
    # 101 rows in the four-ISA wire corpus stop saying PREFETCH and start
    # saying OR.  That is REAL-LOST under R12.1 and it does not become
    # acceptable by being derivable from a QEMU comment: QEMU not modelling
    # Zicbop is an EMULATOR GAP, not a statement that a prefetch is an or,
    # and the standing ruling on upstream gaps is that they are reported as
    # gaps rather than absorbed as tracer answers.  The Capstone key is
    # genuinely finer here and carries information QEMU's rule does not.
    #
    # So the row stays QID_SPLIT -- it states that this identity does not
    # determine the classification -- and the survivor keeps publishing the
    # per-instance answer it publishes today.  It retires when QEMU decodes
    # Zicbop, not before.

    # 0x2b918996 = insn16.decode:173
    #   slli            000 .  .....  ..... 10 @c_shift2
    # One pattern, one trans_ function.  The two candidates -- c.slli and
    # the RV128 shamt-encoding Capstone spells c.slli64 -- agree on every
    # field the wire carries: same opcode GEN_OP_SHL, same branch class,
    # same flags, same lane pair.  They differ ONLY in whether
    # .dep_refine is stated, and that difference is not a fact about the
    # instruction: it comes from Capstone's per-constant encoding-variant
    # table, where one spelling carries a clean single-in/single-out
    # shape and the other's variants are under-tagged.
    #
    # Same disposition, and same reason, as ("x86", 0x1ee): stating the
    # pass-through refiner is the same answer said precisely, it is the
    # shape a shift-by-immediate genuinely has, and the refiner bails by
    # itself on any runtime shape outside that group -- so adopting it
    # can narrow a mask and cannot invent an edge.
    ("riscv", 0x2b918996): (
        "RISCV_INS_C_SLLI64",
        "insn16.decode:173 slli 000 . ..... ..... 10 @c_shift2 -- one "
        "pattern; the candidates agree on opcode, branch class and flags "
        "and differ only in whether the pass-through refiner is stated"),

    # 0x88cd7ecf = target/mips/tcg/translate.c:229
    #   OPC_JR       = 0x08 | OPC_SPECIAL, /* Also JR.HB */
    # QEMU says it in the enumerator's own comment: this opcode IS jr.hb
    # as well as jr.  There is no second decode and no second identity --
    # gen_compute_branch() is reached with op1 == OPC_JR for both, and the
    # hint bits are not consulted.  As with the riscv row above, the two
    # candidates agree on opcode, branch class and flags and differ only
    # in the Capstone-derived .dep_refine annotation.
    ("mips", 0x88cd7ecf): (
        "MIPS_INS_JR_HB",
        "translate.c:229 OPC_JR = 0x08 | OPC_SPECIAL, whose own comment "
        "says `Also JR.HB` -- one opcode for both spellings, hint bits "
        "not consulted; the "
        "candidates differ only in whether the pass-through refiner is "
        "stated"),

    # 0x48fe989e = target/arm/tcg/a64.decode:295
    #   SYS  1101 0101 00 l:1 11 op1:3 crn:4 crm:4 op2:3 rt:5 op0=3
    # One pattern, one trans_ function, and the direction is a FIELD of
    # that pattern: `l` selects read from write, and trans_SYS hands it
    # straight to handle_sys() as `isread`.  Both spellings Capstone
    # gives it -- mrs (l=1) and msr (l=0) -- are the same rule moving one
    # value between a GPR and a system register, and the classifier says
    # so: same opcode GEN_OP_MOV, same branch class, same flags, same
    # (absent) lane pair.  The one field they differ in is whether
    # .dep_refine is stated.
    #
    # Same disposition and same reason as ("x86", 0x1ee), and the reason
    # is checked against dep_passthrough rather than assumed: the shape
    # is one source register into one destination register, which is the
    # single-destination arm's exact subject, and the refiner BAILS
    # WITHOUT PUBLISHING on any runtime shape outside it.  So adopting it
    # can narrow a mask and cannot invent an edge.
    ("aarch64", 0x48fe989e): (
        "AARCH64_INS_MRS",
        "a64.decode:295 SYS 1101 0101 00 l:1 11 op1:3 crn:4 crm:4 op2:3 "
        "rt:5 op0=3 -- one pattern whose `l` field selects the direction "
        "and is passed to handle_sys() as isread; the candidates differ "
        "only in whether the pass-through refiner is stated"),
}


# ---------------------------------------------------------------------------
# QID_BRANCH_CLASS: the transfer class QEMU's own rule states and the
# Capstone key cannot express
# ---------------------------------------------------------------------------
#
# A row here is NOT a second opinion about an ambiguous case.  It is the
# narrow shape where QEMU's decode rule and the Capstone constant observed
# through it are at DIFFERENT GRANULARITIES on the branch class alone: the
# rule names one transfer and the constant names a family that contains
# several.  aarch64 is the whole population -- Capstone spells every
# `b.<cc>` as AARCH64_INS_B, the same constant it gives the unconditional
# `b`, and the condition lives in a field the constant does not carry.
#
# Without this the identity row carried BRANCH_DIRECT_JUMP for a
# conditional branch and the class was recovered PER INSTANCE, at decode
# time, by matching the printed mnemonic "b." -- refine_alias_fields() in
# champsim_tracer_decode.cc.  That route is Capstone's disassembly text,
# which J6 removes from every correctness path; and it can only ever
# repair the instances the tracer decodes, never the identity row a wire
# flip would publish from.  The fact belongs on the row.
#
# THE BAR, and it is the QID_ADJUDICATIONS bar restated for one field:
# the entry may only state what QEMU's decode table itself states, and
# `why` is that source fact, emitted into the generated header beside the
# row.  It may not be used to prefer one classification over another where
# both describe the rule -- that is a taxonomy ruling, not a QEMU fact.
#
# The generator REFUSES an entry that names an identity the universe does
# not contain, and one whose row already carries the branch class it
# states: a ruling that changes nothing is a ruling written against
# evidence that has moved, and it is louder as an error than as a no-op.
QID_BRANCH_CLASS: dict[tuple[str, str], tuple[str, str]] = {
    ("aarch64", "disas_a64/B_cond"): (
        "BRANCH_COND_DIRECT",
        "a64.decode:199 `B_cond 0101010 0 ... c:1 cond:4 imm=%imm19` -- the "
        "rule extracts a 4-bit condition; Capstone spells both b.<cc> and "
        "the unconditional b as AARCH64_INS_B"),
}


def apply_branch_class(info: IsaInfo, entry: Entry, ident: QemuIdent,
                       ) -> tuple[Entry, str | None]:
    """State QEMU's own branch class on the row, where it has one.

    Returns the (possibly rewritten) entry and the source fact that
    rewrote it.  Refuses loudly on a stale entry rather than passing.
    """
    got = QID_BRANCH_CLASS.get((info.key, ident.name))
    if got is None:
        return entry, None
    want, why = got
    if entry.branch == want:
        raise SystemExit(
            f"{info.key}: QID_BRANCH_CLASS names {ident.name} "
            f"(0x{ident.ident:08x}) as {want}, which the row ALREADY "
            f"carries.  A rule that changes nothing is stale against this "
            f"table; delete it or re-state what it is for.")
    import dataclasses
    return dataclasses.replace(entry, branch=want), why


def _branch_class_unreached(info: IsaInfo, idents: list[QemuIdent]) -> None:
    """Every QID_BRANCH_CLASS entry for this ISA must name a real rule."""
    have = {i.name for i in idents}
    for (key, name) in QID_BRANCH_CLASS:
        if key == info.key and name not in have:
            raise SystemExit(
                f"{info.key}: QID_BRANCH_CLASS names {name}, which is not a "
                f"rule in this target's identity universe")


def _pattern_mnemonic_candidates(pattern: str) -> list[str]:
    """Spellings of a decodetree pattern name to try against Capstone.

    decodetree names are QEMU-source identifiers, not mnemonics: ADD_i,
    LDR_v_i, c_fsw.  The trailing _<suffix> parts name the FORM (immediate,
    vector, register), which Capstone folds into the operands rather than
    the mnemonic, so they are peeled one at a time.  Nothing here invents
    a name: every candidate is a prefix of the name QEMU wrote.
    """
    p = pattern.lower()
    out = [p]
    while "_" in p:
        p = p.rsplit("_", 1)[0]
        out.append(p)
    return out


# The i386 emitter fact, and the only place a name is REFUSED because of
# it.  `X86_OP_ENTRYrr` expands to op0 = None: QEMU computes the result
# and the table writes it nowhere.  A row spelled that way whose name is
# a value-producing two-operand ALU op is therefore NOT that op -- it is
# the flags-only form, which is how `cmp` is spelled through a slot named
# SUB and `test` through one named AND.  Those rows have to be OBSERVED;
# the name may not stand in.
#
# The set is deliberately the group-1 ALU ops and nothing wider.  MUL,
# IMUL, DIV and IDIV are ENTRYrr/ENTRYr as well and their destination is
# architecturally implicit (rAX/rDX), so op0 = None there means "the
# generator writes it itself", not "the result is discarded" -- refusing
# those would be the gate mistaking a different fact for this one.
X86_FLAGS_ONLY_REFUSED_OPS = frozenset((
    "GEN_OP_INT_ADD", "GEN_OP_INT_SUB",
    "GEN_OP_AND", "GEN_OP_OR", "GEN_OP_XOR",
))


def x86_emitter_refuses(ident: QemuIdent, entry: Entry) -> bool:
    """Does the row's own operand template contradict its name?"""
    if not (ident.kind == "ENTRYrr" or ident.kind.endswith("/noDest")):
        return False
    return entry.op in X86_FLAGS_ONLY_REFUSED_OPS


@dataclass(frozen=True)
class IdentRow:
    """One QEMU decode identity, carrying the classification it keys."""
    ident: QemuIdent
    entry: Entry
    tier: str
    mnems: tuple[str, ...]          # observed disassembly text, for humans
    # The observed CAPSTONE CONSTANTS, most frequent first.  This is the
    # cardinality key and the disassembly text is not: QEMU prints x86 in
    # AT&T syntax, so one constant appears as cmpb/cmpl/cmpq/cmpw and
    # counting those as four would report an operand-size spelling as a
    # four-way mapping disagreement.  Width is granularity; the constant
    # is the row.
    caps: tuple[str, ...] = ()
    # Observed mnemonics that classify DIFFERENTLY from the row's own
    # payload.  Non-empty means the Capstone key is FINER than QEMU's
    # here: several architectural spellings decode through one rule and
    # the tables give them different answers.  The row keeps the payload
    # of the most frequently observed spelling and says so; it does not
    # average two classifications into a third that describes neither.
    split: tuple[tuple[Entry, tuple[str, ...]], ...] = ()
    refused: str | None = None      # name the emitter fact refused
    # Set when the observations disagreed AND QEMU's own decode-table row
    # settles which of them describes the rule.  The text is the QEMU
    # source fact that decided it, and it is emitted beside the row so the
    # generated header carries the reason and not just the outcome.
    adjudged: str | None = None
    # Set when QEMU's own rule states the row's BRANCH CLASS and the
    # Capstone constant observed through it cannot express one (see
    # QID_BRANCH_CLASS).  The text is that source fact.
    branch_fact: str | None = None


def _refuse_stale_observations(info: IsaInfo, idents: list[QemuIdent],
                               obs: dict[int, dict[str, object]]) -> None:
    """An observation whose id now names a DIFFERENT rule is not evidence.

    A decode id is not stable across source edits, and on i386 it is
    literally __LINE__ in decode-new.c.inc -- inserting a line there
    renumbers every slot after it.  A banked observation carrying a stale
    id would be joined to whatever rule now sits at that id, and the row
    would state a classification QEMU never made through it: a fabricated
    decode, arriving as a promotion rather than as an error.

    That is exactly why the pair census carries the NAME beside the id.
    It was carried and never read until now.  It is read here, and a
    disagreement REFUSES -- re-take the census at this tip rather than
    merging observations across the edit that moved the rule.

    An id the universe does not contain at all is a rule that was renamed
    or removed; the observation has no subject and is dropped, which is
    the safe direction and is already what the join did.
    """
    universe = {i.ident: i.name for i in idents}
    stale = []
    for ident, e in obs.items():
        name = e.get("name")
        if not isinstance(name, str) or name in ("", "-"):
            continue
        now = universe.get(ident)
        if now is not None and now != name:
            stale.append((ident, name, now))
    if stale:
        detail = "; ".join("0x%08x observed as %r, universe now %r"
                           % row for row in sorted(stale)[:8])
        raise SystemExit(
            f"{info.key}: {len(stale)} observation(s) name a rule the "
            f"current decoders do not have at that id -- {detail}.  These "
            f"were taken before an edit moved the rule and joining them "
            f"would state a decode QEMU never made.  Re-take the census at "
            f"this tip.")


def qemu_ident_rows(info: IsaInfo, idents: list[QemuIdent],
                    obs: dict[int, dict[str, object]],
                    existing: dict[str, Entry]) -> list[IdentRow]:
    """Join the identity universe to the classification.

    The identity is the KEY and the classification hangs off it.  Where
    the payload comes from is the row's TIER and the two are not the
    same strength of evidence:

      QID_OBSERVED      QEMU was seen decoding through this rule; the
                        payload is what the decoded instruction is.
      QID_NAME_MATCHED  nothing was observed; the rule's own name in
                        QEMU's source matches a known mnemonic, and the
                        row's operand template does not contradict it.
      QID_NONE          neither.  Residue, named in the census.
    """
    _branch_class_unreached(info, idents)
    m2c = _mnemonic_to_const(info)
    v2c = enum_value_map(info)
    _refuse_stale_observations(info, idents, obs)
    rows: list[IdentRow] = []
    for ident in sorted(idents, key=lambda r: r.ident):
        seen = obs.get(ident.ident)
        mnems: tuple[str, ...] = ()
        tier = QID_NONE
        entry = Entry("GEN_OP_UNKNOWN")
        split: list[tuple[Entry, tuple[str, ...]]] = []
        caps: list[str] = []
        refused = None
        adjudged = None
        if seen:
            mnems = tuple(m for m, _ in seen["mnem"].most_common())
            # Ordered by how often QEMU decoded through this rule with
            # that Capstone id.  The join is id -> id; the disassembly
            # text below is only what the census prints.
            payloads: dict[Entry, list[str]] = {}
            observed_consts: list[str] = []
            for cap, _n in seen["caps"].most_common():
                const = v2c.get(cap)
                if const is None:
                    continue
                cand = full_entry(info, const, existing)
                if cand is None:
                    continue
                observed_consts.append(const)
                caps.append(c_mnemonic(const, info.prefix))
                payloads.setdefault(cand, []).append(
                    c_mnemonic(const, info.prefix))
            if len(payloads) == 1:
                tier = QID_OBSERVED
                entry = next(iter(payloads))
            elif payloads:
                # SEVERAL classifications through one rule.  The row does
                # NOT pick one.
                #
                # It used to take the most frequently observed, and that
                # was wrong in a way only a second run showed: x86 slot
                # 0x6ca carries both spellings of the string move, and
                # adding four short workloads flipped which was more
                # common, so the SAME generator emitted a different table
                # from the same source tree.  A generated file whose
                # content depends on which programs happened to run is
                # not reproducible, and a tie-break by count is a way of
                # averaging while looking like a measurement.
                #
                # So the row states what is true -- this identity does
                # not determine the classification -- and the census
                # names every candidate.  Resolving it needs the
                # instance, not the rule.
                tier = QID_SPLIT
                entry = Entry("GEN_OP_UNKNOWN")
                split = sorted(((e, tuple(sorted(v)))
                                for e, v in payloads.items()),
                               key=lambda x: x[1])
                # ...unless QEMU's own decode-table row settles it.  The
                # adjudication names the surviving candidate BY CAPSTONE
                # CONSTANT, and the constant must be one this rule was
                # actually observed decoding through -- an adjudication
                # written against evidence that no longer exists is a
                # stale ruling applied silently, so it is refused loudly
                # instead.  The payload still comes from full_entry, the
                # one classifier: adjudicating picks among candidates, it
                # never hand-writes a row.
                adj = QID_ADJUDICATIONS.get((info.key, ident.ident))
                if adj is not None:
                    winner, why = adj
                    if winner not in observed_consts:
                        raise SystemExit(
                            f"{info.key}: adjudication for identity "
                            f"0x{ident.ident:08x} ({ident.pattern}) names "
                            f"{winner}, which was NOT observed decoding "
                            f"through it (observed: "
                            f"{', '.join(observed_consts) or 'nothing'}).  "
                            f"The ruling is stale against this evidence; "
                            f"re-adjudicate rather than re-run until it "
                            f"passes.")
                    won = full_entry(info, winner, existing)
                    if won is None:
                        raise SystemExit(
                            f"{info.key}: adjudication for identity "
                            f"0x{ident.ident:08x} names {winner}, which "
                            f"carries no classification at all")
                    tier = QID_ADJUDICATED
                    entry = won
                    adjudged = why
        if tier == QID_NONE:
            for cand_name in _pattern_mnemonic_candidates(ident.pattern):
                const = m2c.get(_norm_mnemonic(cand_name))
                if const is None:
                    continue
                cand = full_entry(info, const, existing)
                if cand is None:
                    continue
                if info.key == "x86" and x86_emitter_refuses(ident, cand):
                    refused = cand.op
                    break
                tier = QID_NAME_MATCHED
                entry = cand
                break
        entry, branch_fact = apply_branch_class(info, entry, ident)
        rows.append(IdentRow(ident, entry, tier, mnems,
                             tuple(sorted(dict.fromkeys(caps))),
                             tuple(split), refused, adjudged, branch_fact))
    return rows


def format_cls_init(entry: Entry) -> str:
    """The InsnClassification initialiser for one identity row."""
    parts = [f".opcode = {entry.op}",
             f".branch_type = {entry.branch}",
             f".flags = {entry.flags}"]
    if entry.refine:
        parts.append(f".refine = {entry.refine}")
    if entry.dep_refine:
        parts.append(f".dep_refine = {entry.dep_refine}")
    if entry.lane_mask_kind != "LANE_MASK_KIND_NONE":
        parts.append(f".lane_mask_kind = {entry.lane_mask_kind}")
        parts.append(f".lane_parallel = {'true' if entry.lane_parallel else 'false'}")
    return "{ " + ", ".join(parts) + " }"


def qemu_ident_header_text(info: IsaInfo, rows: list[IdentRow]) -> str:
    guard = f"CHAMPSIM_TRACER_QEMU_IDENT_{info.key.upper()}_H"
    src = (QEMU_IDENT_SOURCE_TABLES.get(info.key)
           or f"the generated decoders of {QEMU_IDENT_TARGETS[info.key]}")
    what = ("one X86_OP_* row of QEMU's own decode table, keyed by the "
            "source line of\n * its macro expansion"
            if info.key == "x86" else
            "one decodetree pattern -- the trans_<name>() the\n"
            " * translator dispatched to")
    out = [
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "/*",
        f" * QEMU decode-table identity for {info.key} -- auto-generated by",
        f" * {Path(__file__).name} --qemu-ident.  Do not hand-edit a row.",
        " *",
        f" * Each row is {what}: the decision the emulator",
        " * actually made, keyed by the id qemu_plugin_insn_decode_id()",
        " * reports for an instruction decoded through it.  Rows are sorted",
        " * by id so a consumer can bisect.  Universe read from",
        f" *   {src}",
        " *",
        " * .cls is the SAME payload the Capstone-keyed table carries, from",
        " * the SAME classifier (full_entry), under this key instead.  What",
        " * changes is where the classification comes from, not what it says.",
        " *",
        " * .tier says what the classification rests on, and the tiers are",
        " * NOT interchangeable:",
        " *   QID_OBSERVED      QEMU was seen decoding through this rule and",
        " *                     the disassembler named the result",
        " *   QID_NAME_MATCHED  the rule's name matches a known mnemonic, no",
        " *                     decode through it was observed, and the row's",
        " *                     own operand template does not contradict it",
        " *   QID_SPLIT         several spellings were observed decoding",
        " *                     through this one rule and the classifier",
        " *                     gives them different answers, and nothing",
        " *                     in QEMU's row picks between them.  The row",
        " *                     carries NO classification (GEN_OP_UNKNOWN)",
        " *                     and the trailing comment names every",
        " *                     candidate -- resolving one needs the",
        " *                     INSTANCE, not the rule",
        " *   QID_ADJUDICATED   they disagreed and QEMU's own decode-table",
        " *                     row settles it: one candidate is refuted or",
        " *                     strictly subsumed by what the row states.",
        " *                     The payload is that candidate's, from the",
        " *                     same classifier, and the trailing comment",
        " *                     carries the QEMU source fact that decided it",
        " *   QID_NONE          neither -- residue, classification unknown",
        " *",
        " * .cap_split marks a row where the Capstone key is FINER than this",
        " * one: several spellings were observed decoding through the single",
        " * rule and the tables classify them differently.  It is a fact",
        " * about the two KEYS and says nothing about whether the row was",
        " * resolved -- read .tier for that.  A QID_SPLIT row carries no",
        " * classification at all: picking the most frequently observed",
        " * candidate made the generated file depend on which programs",
        " * happened to run, and averaging two classifications into a third",
        " * that describes neither is the one thing it may not do.",
        " *",
        " * SPDX-License-Identifier: GPL-2.0-or-later",
        " * Author: Maccoy Merrell",
        " */",
        "",
        "/*",
        " * enum QemuIdentTier and struct QemuIdentRow are declared ONCE, in",
        " * champsim_tracer_mnemonics.h, exactly as QemuRegRow is for the",
        " * sibling register tables.  A consumer routing by TraceISA includes",
        " * all of these headers in one translation unit, and a type",
        " * emitted per file could not survive that -- the file guard is per",
        " * ISA, so the second include redefined the enum and the struct.",
        " * Nothing ever compiled them together to find out.",
        " */",
        '#include "champsim_tracer_mnemonics.h"',
        "",
        f"static const QemuIdentRow qemu_ident_{info.key}[] = {{",
    ]
    def _note(body: str) -> str:
        """Render one trailing /* ... */ note, refusing a body that would
        break out of it.

        The reasons quote QEMU source, and QEMU source contains comments.
        A reason carrying `/*` or `*/` terminates the generated comment
        early and the header stops compiling -- which is how it was found,
        by quoting `OPC_JR = 0x08 | OPC_SPECIAL, /* Also JR.HB */`
        verbatim.  A generator that can emit an uncompilable header on a
        legal-looking input has a defect, so it refuses here rather than
        writing the file: the fix belongs in the reason text, where a
        human can rephrase it, not in a silent escape that would leave the
        published justification subtly different from what was written.
        """
        if "/*" in body or "*/" in body:
            raise SystemExit(
                "qemu-ident note would break out of its C comment: "
                + body)
        return "  /* " + body + " */"

    for r in rows:
        note = ""
        if r.branch_fact:
            note = _note("branch class from QEMU's rule: " + r.branch_fact)
        elif r.adjudged:
            note = _note(
                "ADJUDICATED from "
                + "; ".join(f"{e.op} <- {', '.join(ms[:3])}"
                            for e, ms in r.split)
                + " -- " + r.adjudged)
        elif r.split:
            note = _note(
                "SPLIT: "
                + "; ".join(f"{e.op} <- {', '.join(ms[:3])}"
                            for e, ms in r.split))
        elif r.mnems:
            note = _note(", ".join(r.mnems[:4]))
        elif r.refused:
            note = _note(f"emitter refused the name -> {r.refused}")
        out.append(f'    {{ 0x{r.ident.ident:08x}u, "{r.ident.name}", '
                   f'{r.tier}, {"true" if r.split else "false"},')
        out.append(f'      {format_cls_init(r.entry)} }},{note}')
    out += [
        "};",
        "",
        f"static const size_t qemu_ident_{info.key}_count =",
        f"    sizeof(qemu_ident_{info.key}) / sizeof(qemu_ident_{info.key}[0]);",
        "",
        f"#endif /* {guard} */",
        "",
    ]
    return "\n".join(out)


def qemu_ident_census(info: IsaInfo, idents: list[QemuIdent],
                      obs: dict[int, dict[str, object]],
                      rows: list[IdentRow], max_lines: int) -> int:
    """The mapping census.  Returns the number of rows with NO payload."""
    import collections
    key = info.key
    print(f"===== {key}: QEMU decode identity as the classification key =====")
    decoders = collections.Counter(i.decoder for i in idents)
    print(f"identity universe            : {len(idents)} rules in "
          f"{len(decoders)} decoders")
    for d, n in decoders.most_common():
        print(f"    {d:<24} {n}")

    if obs:
        # Counted from the CAPS counter, which both sources fill; the
        # mnemonic counter is idprobe-only and using it here would make
        # a pair census read as zero observations.
        total_obs = sum(sum(e["caps"].values()) for e in obs.values())
        unident = obs.get(0)
        print(f"observed translated insns    : {total_obs}")
        if unident is not None:
            n_unident = sum(unident["caps"].values())
            print(f"    carrying a QEMU identity : {total_obs - n_unident} "
                  f"({100.0 * (total_obs - n_unident) / total_obs:.3f}%)")
            print(f"    carrying NONE (id 0)     : {n_unident} "
                  f"({100.0 * n_unident / total_obs:.3f}%)")
        else:
            # A pair census is written from inside the identity reader,
            # which returns on id == 0 before a pair exists to record.
            # Printing 0 here would be a measurement this file cannot
            # make, dressed as one it did.
            print("    carrying NONE (id 0)     : not carried by this "
                  "source; the tracer's own report counts it")
        exercised = [i for i in idents if i.ident in obs]
        print(f"identities exercised         : {len(exercised)} of {len(idents)}")
    else:
        print("observed translated insns    : NONE SUPPLIED -- every row "
              "below rests on its name alone")

    tiers = collections.Counter(r.tier for r in rows)
    print("row provenance:")
    for t in (QID_OBSERVED, QID_ADJUDICATED, QID_SPLIT, QID_NAME_MATCHED,
              QID_NONE):
        print(f"    {t:<18} {tiers.get(t, 0)}")
    refused = [r for r in rows if r.refused]
    if refused:
        print(f"    names REFUSED by the row's own operand template: "
              f"{len(refused)}")
        for r in refused[:max_lines]:
            print(f"        0x{r.ident.ident:08x} {r.ident.name} "
                  f"[{r.ident.kind}] would have taken {r.refused}")

    # ---- the mapping census proper, over OBSERVED decodes only.  A
    # name-matched row asserts nothing about cardinality and is excluded
    # on purpose: it has no second key to be compared against.
    id2mn: dict[int, set] = {}
    mn2id: dict[str, set] = {}
    for r in rows:
        if r.tier not in (QID_OBSERVED, QID_ADJUDICATED, QID_SPLIT):
            continue
        id2mn[r.ident.ident] = set(r.caps)
        for m in r.caps:
            mn2id.setdefault(m, set()).add(r.ident.ident)
    one_one = sum(1 for i, ms in id2mn.items()
                  if len(ms) == 1 and len(mn2id[next(iter(ms))]) == 1)
    many_one = sorted(((i, ms) for i, ms in id2mn.items() if len(ms) > 1),
                      key=lambda x: -len(x[1]))
    one_many = sorted(((m, ids) for m, ids in mn2id.items() if len(ids) > 1),
                      key=lambda x: -len(x[1]))
    byid = {i.ident: i for i in idents}
    print(f"MAPPING CENSUS over {len(id2mn)} exercised identities, counted "
          f"in TABLE ROWS (Capstone constants), not in printed mnemonics:")
    print(f"    1:1  identity <-> row               : {one_one}")
    print(f"    N:1  one identity, many rows        : {len(many_one)}")
    print(f"    1:N  one row, many identities       : {len(one_many)}")
    for i, ms in many_one[:max_lines]:
        print(f"        {byid[i].name:<28} {len(ms)}: "
              f"{', '.join(sorted(ms)[:8])}")
    for m, ids in one_many[:max_lines]:
        names = sorted(byid[i].name for i in ids)
        print(f"        {m:<16} {len(ids)}: {', '.join(names[:6])}")

    # ---- the rows where the two keys DISAGREE about the classification.
    # This is the whole of what re-keying changes, and it is per row.
    split = [r for r in rows if r.tier == QID_SPLIT]
    print(f"SPLIT -- one identity, several classifications observed: "
          f"{len(split)}")
    def _delta(a: Entry, b: Entry) -> str:
        """Name the fields two payloads disagree on, and only those."""
        out = []
        for f in ("op", "branch", "flags", "refine", "dep_refine",
                  "lane_mask_kind", "lane_parallel"):
            av, bv = getattr(a, f), getattr(b, f)
            if av != bv:
                out.append(f"{f}: {av} -> {bv}")
        return "; ".join(out) or "(identical payload -- should not be split)"

    for r in split:
        print(f"    0x{r.ident.ident:08x} {r.ident.name}   "
              f"-> row carries NO classification")
        base = r.split[0][0]
        for i, (e, ms) in enumerate(r.split):
            print(f"        candidate {e.op:<22} <- {', '.join(ms)}")
            if i:
                print(f"                  {_delta(base, e)}")

    adj = [r for r in rows if r.tier == QID_ADJUDICATED]
    print(f"ADJUDICATED -- the split rows QEMU's own decode-table row "
          f"decides: {len(adj)}")
    for r in adj:
        print(f"    0x{r.ident.ident:08x} {r.ident.name}   -> {r.entry.op}")
        for e, ms in r.split:
            if e == r.entry:
                print(f"        KEPT      {e.op:<22} <- {', '.join(ms)}")
                continue
            # Name the fields the dropped candidate disagreed on, not only
            # its opcode: several of these rows agree on the opcode and
            # part on a refiner, and printing "REFUTED GEN_OP_VEC_MOV"
            # against a KEPT GEN_OP_VEC_MOV says nothing about what moved.
            print(f"        DROPPED   {e.op:<22} <- {', '.join(ms)}")
            print(f"                  {_delta(r.entry, e)}")
        print(f"        because: {r.adjudged}")

    # ---- the residue, BY NAME.  A count would hide which rules the
    # tracer would have nothing to say about.
    residue = [r for r in rows if r.tier == QID_NONE]
    live = [r for r in residue if r.ident.ident in obs]
    print(f"NO ROW -- identities with no classification at all: "
          f"{len(residue)} ({len(live)} of them EXERCISED)")
    for r in residue:
        mark = "  <-- EXERCISED" if r.ident.ident in obs else ""
        print(f"    {r.ident.name}  ({r.ident.src_file}:"
              f"{r.ident.src_line}){mark}")
    return len(live)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isa", choices=sorted(ISAS), action="append", help="limit to one ISA; repeatable")
    parser.add_argument("--diff", action="store_true", help="print missing/mismatched entries")
    parser.add_argument("--apply", action="store_true", help="rewrite mnemonic tables in place")
    parser.add_argument("--regs", action="store_true", help="audit/rewrite register tables instead of instruction tables")
    parser.add_argument("--max-lines", type=int, default=40, help="maximum diff rows per section")
    parser.add_argument("--qemu-regs", action="store_true",
                        help="census/regenerate the QEMU-indexed register tables "
                             "(one row per register in QEMU's GDB-stub namespace)")
    parser.add_argument("--qemu-ident", action="store_true",
                        help="census/regenerate tables keyed on QEMU's own decode identity "
                             "(decodetree targets only)")
    parser.add_argument("--build-dir", type=Path,
                        help="QEMU build directory holding the generated decoders "
                             "(required with --qemu-ident on a decodetree target)")
    parser.add_argument("--observed", type=Path, nargs="*", default=[],
                        help="idprobe TSV files supplying OBSERVED decodes")
    parser.add_argument("--pairs", type=Path, nargs="*", default=[],
                        help="pair-census files (CST_QEMU_IDENT_PAIRS output) "
                             "supplying OBSERVED (identity, capstone-id) "
                             "joins; preferred over --observed, and the only "
                             "source that works on riscv64 and mipsel")
    args = parser.parse_args()
    if not args.diff and not args.apply:
        parser.error("choose --diff and/or --apply")
    if args.qemu_ident and args.build_dir is None:
        wanted = set(args.isa or sorted(ISAS))
        if wanted - set(QEMU_IDENT_SOURCE_TABLES):
            parser.error("--qemu-ident needs --build-dir for a decodetree target")
    keys = args.isa or sorted(ISAS)
    total = 0
    if args.qemu_regs:
        for key in keys:
            info = ISAS[key]
            rows, conflicts = qemu_reg_rows(info)
            if args.diff:
                total += qemu_regs_census(info, rows, conflicts,
                                          max_lines=args.max_lines)
            if args.apply:
                total += apply_qemu_regs_one(info)
        return 1 if total else 0
    if args.qemu_ident:
        for key in keys:
            if key not in QEMU_IDENT_TARGETS and key not in QEMU_IDENT_SOURCE_TABLES:
                print(f"===== {key}: no identity universe to read, skipped =====")
                continue
            info = ISAS[key]
            idents = qemu_ident_universe(args.build_dir, key)
            # The observed set is per ISA: pointing every target at every
            # TSV would join one target's ids against another's, and the
            # ids are explicitly not comparable across targets.
            # THE CORPUS IS IN THE TREE.  Without an explicit --pairs the
            # generator reads ident_corpus/, the banked union census that
            # tools/merge_ident_pairs.py maintains, so `--qemu-ident --apply`
            # reproduces the shipped headers from the checkout alone.  Before
            # that bank existed the observed set was whatever run directories
            # the author had to hand, and EXEC57 measured what that costs: a
            # fresh whole-battery corpus reached FEWER rules than the shipped
            # tables carry, so regenerating would have DEMOTED 104 rows that
            # already answer, and the pass correctly refused to regenerate at
            # all.  A generated file has to be derivable from the tree.
            pair_paths = [p for p in args.pairs
                          if _observed_matches_isa(Path(p), key)]
            if not args.pairs:
                banked = IDENT_CORPUS_DIR / f"pairs_{key}.tsv"
                if not banked.is_file():
                    parser.error(
                        f"no banked pair census at {banked} and no --pairs "
                        f"given -- refusing to generate an identity table "
                        f"from an empty observed set, which would demote "
                        f"every OBSERVED row to NAME_MATCHED or NONE")
                pair_paths = [banked]
            if pair_paths:
                obs = load_pairs(pair_paths)
            else:
                paths = [p for p in args.observed
                         if _observed_matches_isa(Path(p), key)]
                obs = load_observed(paths) if paths else {}
            rows = qemu_ident_rows(info, idents, obs, parse_existing(info))
            if args.diff:
                total += qemu_ident_census(info, idents, obs, rows,
                                           max_lines=args.max_lines)
            if args.apply:
                out = PLUGIN_DIR / f"champsim_tracer_qemu_ident_{key}.h"
                out.write_text(qemu_ident_header_text(info, rows))
                print(f"wrote {out}")
        return 1 if args.diff and total else 0
    if args.diff:
        for key in keys:
            if args.regs:
                total += audit_regs_one(ISAS[key], max_lines=args.max_lines)
            else:
                total += audit_one(ISAS[key], max_lines=args.max_lines)
    if args.apply:
        for key in keys:
            if args.regs:
                apply_regs_one(ISAS[key])
            else:
                apply_one(ISAS[key])
            print(f"rewrote {ISAS[key].header}")
    return 1 if args.diff and total else 0


if __name__ == "__main__":
    sys.exit(main())