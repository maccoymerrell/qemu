"""Sphinx extension: generate the encoding-mappings appendix.

Parses the four per-ISA classification tables next to the plugin
source (``champsim_tracer_mnemonics_*.h``) and emits an RST page
under ``<srcdir>/_generated/encoding_tables.rst`` documenting how
every Capstone encoding-id (instruction *and* register) maps into
the generic domain.

We use "encoding" as the umbrella term throughout this appendix —
each row is a Capstone-side identifier (``X86_INS_*`` for an
instruction, ``X86_REG_*`` for a register, etc.) being assigned a
generic-domain ID.  "Mnemonic" is reserved for the human-readable
assembly form (``"mov rax, rbx"``).

The page is regenerated on every Sphinx invocation so the
documentation can never lag the source — and the generated file is
listed in ``.gitignore`` so the regeneration produces no diff
churn.

Wired into the toctree from ``index.rst`` as
``_generated/encoding_tables``.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from typing import Iterable

from sphinx.application import Sphinx


# ---------------------------------------------------------------------------
# Per-ISA inputs.
# ---------------------------------------------------------------------------

# Each tuple is (display name, header filename,
#                 insn-id Capstone prefix, register-id Capstone prefix).
ISA_FILES: list[tuple[str, str, str, str]] = [
    ("x86_64",  "champsim_tracer_mnemonics_x86.h",
                "X86_INS_",     "X86_REG_"),
    ("AArch64", "champsim_tracer_mnemonics_aarch64.h",
                "AARCH64_INS_", "AARCH64_REG_"),
    ("RISC-V",  "champsim_tracer_mnemonics_riscv.h",
                "RISCV_INS_",   "RISCV_REG_"),
    ("MIPS",    "champsim_tracer_mnemonics_mips.h",
                "MIPS_INS_",    "MIPS_REG_"),
]


# Match `[ISA_INS_FOO] = { GEN_OP_X, BRANCH_Y, MF_Z[ | MF_W ...] [, .refine ...] },`
# tolerating arbitrary whitespace and line breaks inside the brace block.
INSN_RE = re.compile(
    r"\[\s*(?P<insn>[A-Z][A-Z0-9_]*_INS_[A-Z0-9_]+)\s*\]"
    r"\s*=\s*\{\s*"
    r"(?P<op>GEN_OP_[A-Z0-9_]+)\s*,\s*"
    r"(?P<branch>BRANCH_[A-Z0-9_]+)\s*,\s*"
    r"(?P<flags>MF_[A-Z0-9_]+(?:\s*\|\s*MF_[A-Z0-9_]+)*)",
    re.MULTILINE,
)


# Match the whole `[ISA_REG_FOO] = { ... }` initialiser so we can
# inspect both the singleton ``.reg_id`` form and the multi-register
# ``.regs = { REG_A, REG_B, ... }`` form RISC-V's V*M* tuples use.
# Lazy match the brace body so a row terminates at its own closing
# brace.
REG_BLOCK_RE = re.compile(
    r"\[\s*(?P<reg>[A-Z][A-Z0-9_]*_REG_[A-Z0-9_]+)\s*\]"
    r"\s*=\s*\{(?P<body>[^{}]*(?:\{[^{}]*\}[^{}]*)*)\}",
    re.MULTILINE,
)

# Within the block: pick out the .reg_id assignment (always
# present) and the optional .regs={...} list.
REG_ID_RE = re.compile(r"\.reg_id\s*=\s*(REG_[A-Z0-9_]+)")
REG_LIST_RE = re.compile(
    r"\.regs\s*=\s*\{\s*(?P<list>(?:REG_[A-Z0-9_]+\s*,?\s*)+)\}"
)


# ---------------------------------------------------------------------------
# Display helpers — strip the namespace prefixes so the tables aren't full
# of redundant noise.
# ---------------------------------------------------------------------------

def short_with_prefix(name: str, prefix: str) -> str:
    return name[len(prefix):] if name.startswith(prefix) else name


def short_op(op: str) -> str:
    return op[len("GEN_OP_"):] if op.startswith("GEN_OP_") else op


def short_reg(reg: str) -> str:
    return reg[len("REG_"):] if reg.startswith("REG_") else reg


# Match a dense-bank register name with a numeric suffix: REG_VEC12
# yields ("REG_VEC", 12).  Returns None for irregular names like
# REG_FLAGS / REG_SP that aren't part of an indexed bank.
_BANK_RE = re.compile(r"^(REG_[A-Z]+?)(\d+)$")


def collapse_reg_list(gens: list[str]) -> str:
    """Render a list of generic-register IDs compactly.

    Consecutive entries in the same dense bank — e.g.
    ``REG_VEC0, REG_VEC1, ..., REG_VEC7`` — collapse to
    ``REG_VEC0..VEC7``.  Mixed lists fall back to a comma-separated
    enumeration so RISC-V's V*M* tuples read as a tight range while
    a hypothetical heterogeneous group would still be lossless.
    """
    if not gens:
        return ""
    if len(gens) == 1:
        return f"``{short_reg(gens[0])}``"

    # Try to read the list as a single dense-bank run.
    parsed: list[tuple[str, int]] = []
    for g in gens:
        m = _BANK_RE.match(g)
        if not m:
            parsed = []
            break
        parsed.append((m.group(1), int(m.group(2))))

    if parsed:
        bank = parsed[0][0]
        start = parsed[0][1]
        if (all(p[0] == bank for p in parsed) and
                all(parsed[i][1] == start + i for i in range(len(parsed)))):
            end = parsed[-1][1]
            return (f"``{short_reg(bank)}{start}"
                    f"..{short_reg(bank)}{end}``")

    return ", ".join(f"``{short_reg(g)}``" for g in gens)


_BRANCH_SHORT = {
    "BRANCH_NONE":          "—",
    "BRANCH_DIRECT_JUMP":   "direct",
    "BRANCH_INDIRECT_JUMP": "indirect",
    "BRANCH_RETURN":        "return",
    "BRANCH_COND_DIRECT":   "cond-direct",
    "BRANCH_SYSCALL_TYPE":  "syscall",
}


def short_branch(b: str) -> str:
    return _BRANCH_SHORT.get(b, b.removeprefix("BRANCH_").lower())


_FLAG_SHORT = {
    "MF_NONE":        "—",
    "MF_ATOMIC":      "atomic",
    "MF_CONDITIONAL": "cond",
}


def short_flags(f: str) -> str:
    parts = [p.strip() for p in f.split("|")]
    pretty = [_FLAG_SHORT.get(p, p.removeprefix("MF_").lower()) for p in parts]
    pretty = [p for p in pretty if p != "—"]
    return ", ".join(pretty) if pretty else "—"


# ---------------------------------------------------------------------------
# Parsing.
# ---------------------------------------------------------------------------

def parse_insn_rows(text: str, prefix: str
                    ) -> list[tuple[str, str, str, str]]:
    """Return [(insn, gen_op, branch_type, flags)] sorted by insn."""
    rows: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for m in INSN_RE.finditer(text):
        insn = m.group("insn")
        if not insn.startswith(prefix):
            continue
        if insn in seen:
            continue
        seen.add(insn)
        rows.append(
            (insn, m.group("op"), m.group("branch"), m.group("flags"))
        )
    rows.sort(key=lambda r: r[0])
    return rows


def parse_reg_rows(text: str, prefix: str
                   ) -> list[tuple[str, list[str]]]:
    """Return [(capstone_reg, [generic_reg, ...])] sorted by capstone name.

    Each row's generic-side payload is a list because a single
    Capstone register encoding may alias to multiple generic IDs at
    once: RISC-V's ``V0M8`` etc. expose a register group of 2/4/8
    consecutive vector registers via ``.regs = { ... }``.  The
    classifier treats *all* of those as touched whenever the
    encoding appears as a source or destination operand, so the
    lookup table needs to reflect the full set rather than just
    the leading ``.reg_id``.
    """
    rows: list[tuple[str, list[str]]] = []
    seen: set[str] = set()
    for m in REG_BLOCK_RE.finditer(text):
        reg = m.group("reg")
        if not reg.startswith(prefix):
            continue
        if reg in seen:
            continue
        body = m.group("body")
        list_match = REG_LIST_RE.search(body)
        if list_match:
            gens = [r.strip() for r in list_match.group("list").split(",")]
            gens = [g for g in gens if g]
        else:
            id_match = REG_ID_RE.search(body)
            if not id_match:
                continue  # Malformed row; skip.
            gens = [id_match.group(1)]
        seen.add(reg)
        rows.append((reg, gens))
    rows.sort(key=lambda r: r[0])
    return rows


# ---------------------------------------------------------------------------
# RST emission.
# ---------------------------------------------------------------------------

def _rst_table(headers: list[str], rows: Iterable[Iterable[str]],
               widths: list[int]) -> list[str]:
    out = [
        ".. list-table::",
        "   :header-rows: 1",
        f"   :widths: {' '.join(str(w) for w in widths)}",
        "",
    ]
    out.append("   * - " + headers[0])
    for h in headers[1:]:
        out.append("     - " + h)
    for row in rows:
        cells = list(row)
        out.append("   * - " + cells[0])
        for c in cells[1:]:
            out.append("     - " + c)
    out.append("")
    return out


def emit_per_isa_section(name: str, insn_prefix: str, reg_prefix: str,
                         insn_rows: list[tuple[str, str, str, str]],
                         reg_rows: list[tuple[str, list[str]]]
                         ) -> list[str]:
    out: list[str] = []
    out.append(name)
    out.append("-" * len(name))
    out.append("")

    # ---- Instructions ----
    # Include the ISA name in the sub-heading so autosectionlabel
    # doesn't collide across the four per-ISA sections.
    sub = f"{name} — instruction encodings"
    out.append(sub)
    out.append("~" * len(sub))
    out.append("")
    out.append(
        f"{len(insn_rows)} Capstone instruction-ids classified.  "
        f"The ``{insn_prefix}`` prefix is dropped from the *Insn* "
        "column, and the ``GEN_OP_`` / ``BRANCH_`` / ``MF_`` prefixes "
        "from the value columns, for compactness."
    )
    out.append("")
    table = (
        (
            f"``{short_with_prefix(insn, insn_prefix)}``",
            f"``{short_op(op)}``",
            short_branch(branch),
            short_flags(flags),
        )
        for insn, op, branch, flags in insn_rows
    )
    out.extend(_rst_table(
        ["Insn", "Generic op", "Branch type", "Flags"],
        table,
        widths=[28, 22, 14, 18],
    ))

    # ---- Registers ----
    sub = f"{name} — register encodings"
    out.append(sub)
    out.append("~" * len(sub))
    out.append("")
    multi = sum(1 for _, gens in reg_rows if len(gens) > 1)
    multi_note = ""
    if multi:
        multi_note = (
            f"  {multi} encoding(s) alias to a *group* of generic IDs "
            "(RISC-V ``V*M*`` register-group tuples expand to "
            "consecutive ``REG_VEC*`` entries); those rows render the "
            "full range like ``VEC0..VEC7``."
        )
    out.append(
        f"{len(reg_rows)} Capstone register-ids classified.  Multiple "
        "Capstone names typically map to the same generic-domain ID — "
        "for example x86 ``AH``, ``AL``, ``AX``, ``EAX``, ``RAX`` "
        f"all alias to ``REG_GPR0``.  The ``{reg_prefix}`` and "
        "``REG_`` prefixes are stripped." + multi_note
    )
    out.append("")
    table = (
        (
            f"``{short_with_prefix(reg, reg_prefix)}``",
            collapse_reg_list(gens),
        )
        for reg, gens in reg_rows
    )
    out.extend(_rst_table(
        ["Capstone reg", "Generic reg id(s)"],
        table,
        widths=[40, 60],
    ))
    return out


def emit_by_genop_section(per_isa_rows) -> list[str]:
    """For each GEN_OP, list which insns from each ISA map to it."""
    by_op: dict[str, dict[str, list[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for isa_name, (insn_prefix, _reg_prefix, insn_rows, _reg_rows) in (
            per_isa_rows.items()):
        for insn, op, _branch, _flags in insn_rows:
            by_op[op][isa_name].append(short_with_prefix(insn, insn_prefix))

    out: list[str] = []
    out.append("By generic opcode")
    out.append("~~~~~~~~~~~~~~~~~")
    out.append("")
    out.append(
        "For each ``GEN_OP_*`` value, every instruction encoding "
        "that maps to it on any supported ISA.  Useful when "
        "answering *what does this opcode actually represent?*"
    )
    out.append("")
    for op in sorted(by_op):
        out.append(f"``{op}``")
        out.append("^" * (len(op) + 4))
        out.append("")
        for isa in sorted(by_op[op]):
            mnemonics = sorted(by_op[op][isa])
            joined = ", ".join(f"``{m}``" for m in mnemonics)
            out.append(f"**{isa}** ({len(mnemonics)}): {joined}")
            out.append("")
    return out


def emit_by_genreg_section(per_isa_rows) -> list[str]:
    """For each REG_*, list which Capstone register names alias to it."""
    by_reg: dict[str, dict[str, list[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for isa_name, (_insn_prefix, reg_prefix, _insn_rows, reg_rows) in (
            per_isa_rows.items()):
        for cap_reg, gens in reg_rows:
            for gen in gens:
                by_reg[gen][isa_name].append(
                    short_with_prefix(cap_reg, reg_prefix)
                )

    out: list[str] = []
    out.append("By generic register id")
    out.append("~~~~~~~~~~~~~~~~~~~~~~")
    out.append("")
    out.append(
        "For each ``REG_*`` value, every Capstone register name that "
        "aliases to it.  Most generic IDs aggregate many architectural "
        "register sub-views — 8/16/32/64-bit aliases of the same "
        "underlying GPR; SVE / NEON sub-views; predicate variants. "
        "The companion table in :doc:`/reference` describes each ID's "
        "class membership."
    )
    out.append("")
    for gen in sorted(by_reg):
        out.append(f"``{gen}``")
        out.append("^" * (len(gen) + 4))
        out.append("")
        for isa in sorted(by_reg[gen]):
            names = sorted(set(by_reg[gen][isa]))
            joined = ", ".join(f"``{n}``" for n in names)
            out.append(f"**{isa}** ({len(names)}): {joined}")
            out.append("")
    return out


def emit_by_branch_section(per_isa_rows) -> list[str]:
    """For each non-NONE branch type, list the insns that drive it."""
    by_branch: dict[str, dict[str, list[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for isa_name, (insn_prefix, _reg_prefix, insn_rows, _reg_rows) in (
            per_isa_rows.items()):
        for insn, _op, branch, _flags in insn_rows:
            if branch == "BRANCH_NONE":
                continue
            by_branch[branch][isa_name].append(
                short_with_prefix(insn, insn_prefix)
            )

    out: list[str] = []
    out.append("By branch type")
    out.append("~~~~~~~~~~~~~~")
    out.append("")
    out.append(
        "Instruction encodings whose classifier row sets a "
        "non-``NONE`` ``BranchType``, grouped by that type. "
        "Capstone insn-ids that *can* dynamically resolve to a "
        "different branch type via a ``.refine`` callback (notably "
        "x86 ``CALL`` and ``JMP`` becoming ``INDIRECT_JUMP`` on a "
        "register / memory operand) are listed under their "
        "*table-default* branch type here, not their refined one."
    )
    out.append("")
    for branch in sorted(by_branch):
        out.append(f"``{branch}``")
        out.append("^" * (len(branch) + 4))
        out.append("")
        for isa in sorted(by_branch[branch]):
            names = sorted(by_branch[branch][isa])
            joined = ", ".join(f"``{n}``" for n in names)
            out.append(f"**{isa}** ({len(names)}): {joined}")
            out.append("")
    return out


# ---------------------------------------------------------------------------
# Sphinx hook.
# ---------------------------------------------------------------------------

def write_appendix(app: Sphinx) -> None:
    src = app.srcdir
    parent = os.path.dirname(src)
    out_dir = os.path.join(src, "_generated")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "encoding_tables.rst")

    per_isa: dict[str, tuple[str, str,
                              list[tuple[str, str, str, str]],
                              list[tuple[str, str]]]] = {}
    missing: list[str] = []
    for isa_name, filename, insn_prefix, reg_prefix in ISA_FILES:
        path = os.path.join(parent, filename)
        if not os.path.exists(path):
            missing.append(filename)
            continue
        with open(path, encoding="utf-8") as f:
            text = f.read()
        per_isa[isa_name] = (
            insn_prefix,
            reg_prefix,
            parse_insn_rows(text, insn_prefix),
            parse_reg_rows(text, reg_prefix),
        )

    lines: list[str] = []
    lines.append("Appendix: encoding mappings")
    lines.append("===========================")
    lines.append("")
    lines.append(
        "Auto-generated from the per-ISA classification tables in "
        "``champsim_tracer_mnemonics_*.h`` at build time.  This page "
        "answers two lookup questions every prospective producer of "
        "a ``.cst`` trace asks:"
    )
    lines.append("")
    lines.append(
        "* *Given an instruction encoding* X *on ISA* Y, *what generic "
        "opcode* / *branch type* / *classifier flags* does the QEMU "
        "plugin assign to it?*"
    )
    lines.append(
        "* *Given an architectural register encoding* X *on ISA* Y, "
        "*what generic-domain* ``REG_*`` *id does the plugin map it to?*"
    )
    lines.append("")
    lines.append(
        "Two views.  The :ref:`per-ISA tables <ix-per-isa>` give the "
        "direct lookup; the :ref:`inverted views <ix-by-genid>` go "
        "the other way so you can see what every ``GEN_OP_*`` and "
        "``REG_*`` value actually covers in practice."
    )
    lines.append("")
    if missing:
        lines.append(".. warning::")
        lines.append("")
        lines.append(
            f"   Source headers not found at build time: "
            f"{', '.join(missing)}.  Affected ISA sections are "
            "skipped."
        )
        lines.append("")

    # --- Per-ISA tables ---
    lines.append(".. _ix-per-isa:")
    lines.append("")
    lines.append("Per-ISA tables")
    lines.append("--------------")
    lines.append("")
    for isa_name, _filename, insn_prefix, reg_prefix in ISA_FILES:
        if isa_name not in per_isa:
            continue
        _ip, _rp, insn_rows, reg_rows = per_isa[isa_name]
        lines.extend(emit_per_isa_section(
            isa_name, insn_prefix, reg_prefix, insn_rows, reg_rows,
        ))

    # --- Inverted views ---
    lines.append(".. _ix-by-genid:")
    lines.append("")
    lines.append("Inverted views")
    lines.append("--------------")
    lines.append("")
    lines.extend(emit_by_genop_section(per_isa))
    lines.extend(emit_by_genreg_section(per_isa))
    lines.extend(emit_by_branch_section(per_isa))

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
        f.write("\n")


def setup(app: Sphinx) -> dict[str, object]:
    app.connect("builder-inited", write_appendix)
    return {
        "version": "0.1",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
