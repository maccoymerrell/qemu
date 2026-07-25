"""Self-modifying-code (SMC) workload family for the validator.

The plugin mints a new template *revision* (a fresh template_id at an already-
committed start_pc) when correct-path code re-executes with different bytes,
and reuses a prior revision's id when the guest restores a previously-seen
state.  See ``contrib/plugins/champsim_tracer/smc_plan.md``.

Minting is **shape-agnostic**: the discriminator compares the OVERLAPPING
PREFIX of the committed template and the freshly-assembled block, so a rewrite
is detected whether it patches bytes in place, moves the block's instruction
boundaries, or changes the instruction count outright.  Only a difference in
EXTENT with a byte-identical overlap — an assembly artifact — mints nothing.

Each family builds a tiny value-returning function in an RWX page, rewrites it,
syncs the icache, and re-executes.  Four *shapes* are available (the per-ISA
encoders mirror each other in ``enc()`` and ``shape_insns()``):

  ``A``  load-immediate ; return                      (the short shape)
  ``B``  zero ; add-immediate ; return                (one instruction more)
  ``P``  nop ; nop ; load-immediate ; return          (two narrow nops)
  ``Q``  wide-nop ; load-immediate ; return           (P's byte count, fewer
                                                       instructions)

``P``/``Q`` need a variable-width encoding and so exist only on ``x86_64``
(1-byte ``nop`` vs 2-byte ``xchg %ax,%ax``) and ``riscv64`` (2-byte ``c.nop``
vs 4-byte ``nop``); the fixed-width ISAs skip the boundary-shift family.

Families
--------

Same-shape (byte patches that keep the instruction boundaries):

  * ``patch_once``     — states A, B                → exactly 2 revisions
  * ``flip_flop``      — states A, B, A, B          → exactly 2 revisions (the
                         returning states reuse their original ids)
  * ``cap_overflow``   — 5 states, ``smc_revisions=2`` → 2 revisions kept
                         (minting stops; a LOUD warning fires)
  * ``write_no_exec``  — write 4 states, execute only the first → 1 template
                         (writes that never re-execute never surface)

Shape-changing (the rewrite moves instruction boundaries or the instruction
count — the common real case: kernel alternatives and static-key patching, JIT
re-emission):

  * ``grow``           — shape A then shape B, one immediate → 2 revisions,
                         the second holding one instruction MORE
  * ``shrink``         — shape B then shape A → 2 revisions, the second
                         holding one instruction FEWER
  * ``boundary_shift`` — shape P then shape Q: the SAME number of code bytes
                         re-cut into different instructions → 2 revisions
  * ``grow_return``    — A, B, A → exactly 2 revisions; the returning A reuses
                         its ORIGINAL template id, proving content-signature
                         reuse survives a shape change

Negative control:

  * ``rewrite_identical`` — the identical bytes rewritten and re-executed four
                         times → 1 template, 0 revisions.  Re-commit churn on
                         unchanged code must never mint.

The extent-artifact branch of the discriminator (byte-identical overlap,
different extent) cannot be reached from a guest program — the fault machinery
merges an interrupted chain back into a whole BB and the wrong-path walker only
commits sealed BBs — so it is covered directly by the host-side truth table in
``run_discriminator_truth_table``, which drives
``champsim_tracer_smc_match.h`` over every branch of the decision.

The oracle groups the decoded templates by start_pc, matches them against the
family's known per-shape byte images, and asserts the exact revision structure
AND that the body's template references resolve to the right revision at each
position.  Self-contained: it does not go through the diamond-CFG validator
(the SMC program is not a diamond).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# Shapes each ISA can encode.  P/Q need a variable-width instruction encoding.
ISA_SHAPES = {
    "x86_64":  "ABPQ",
    "aarch64": "AB",
    "riscv64": "ABPQ",
    "mipsel":  "AB",
}

# Every family: the shape written at each step, the immediate each step
# encodes, the number of DISTINCT template revisions expected at the self-
# modified pc, and the optional knobs (revision cap / execute-first-step-only).
FAMILIES = {
    "patch_once":       {"shapes": "AA",    "imms": [0x101, 0x202],
                         "revisions": 2},
    "flip_flop":        {"shapes": "AAAA",  "imms": [0x101, 0x202,
                                                     0x101, 0x202],
                         "revisions": 2},
    "cap_overflow":     {"shapes": "AAAAA", "imms": [0x101, 0x202, 0x303,
                                                     0x404, 0x505],
                         "revisions": 2, "cap": 2},
    "write_no_exec":    {"shapes": "AAAA",  "imms": [0x101, 0x202,
                                                     0x303, 0x404],
                         "revisions": 1, "first_only": True},
    # --- shape-changing -------------------------------------------------
    "grow":             {"shapes": "AB",    "imms": [0x101, 0x101],
                         "revisions": 2},
    "shrink":           {"shapes": "BA",    "imms": [0x101, 0x101],
                         "revisions": 2},
    "boundary_shift":   {"shapes": "PQ",    "imms": [0x101, 0x101],
                         "revisions": 2},
    "grow_return":      {"shapes": "ABA",   "imms": [0x101, 0x101, 0x101],
                         "revisions": 2},
    # --- negative control -----------------------------------------------
    "rewrite_identical": {"shapes": "AAAA", "imms": [0x101] * 4,
                          "revisions": 1},
}

# Driven in this order by run_families / the features tier.
FAMILY_ORDER = ("patch_once", "flip_flop", "cap_overflow", "write_no_exec",
                "grow", "shrink", "boundary_shift", "grow_return",
                "rewrite_identical")

# How many times each written state is executed before the next rewrite.
EXEC_EACH = 3

C_SOURCE = r"""
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>

#ifndef SMC_SHAPES
#define SMC_SHAPES "AA"
#endif
#ifndef SMC_IMMS
#define SMC_IMMS { 0x101, 0x202 }
#endif
#ifndef SMC_FIRST_ONLY
#define SMC_FIRST_ONLY 0
#endif
#ifndef SMC_EXEC_EACH
#define SMC_EXEC_EACH 3
#endif

/*
 * Encode one shape of the self-modified block into a zeroed 16-byte body.
 * Returns the encoded length, or 0 when the shape has no encoding on this ISA
 * (the boundary-shift shapes on a fixed-width ISA).  Every shape ends in the
 * ISA's return instruction, so the block is a complete true basic block whose
 * start_pc is the call target.
 */
static unsigned enc(uint8_t *b, char s, uint32_t imm)
{
    memset(b, 0, 16);
#if defined(__x86_64__)
    uint32_t i = imm;
    /* A: mov $imm,%eax ; ret                              (2 insns,  6 bytes) */
    if (s == 'A') { b[0] = 0xB8; memcpy(b + 1, &i, 4); b[5] = 0xC3; return 6; }
    /* B: xor %eax,%eax ; add $imm,%eax ; ret              (3 insns,  8 bytes) */
    if (s == 'B') { b[0] = 0x31; b[1] = 0xC0; b[2] = 0x05;
                    memcpy(b + 3, &i, 4); b[7] = 0xC3; return 8; }
    /* P: nop ; nop ; mov $imm,%eax ; ret                  (4 insns,  8 bytes) */
    if (s == 'P') { b[0] = 0x90; b[1] = 0x90; b[2] = 0xB8;
                    memcpy(b + 3, &i, 4); b[7] = 0xC3; return 8; }
    /* Q: xchg %ax,%ax ; mov $imm,%eax ; ret               (3 insns,  8 bytes) */
    if (s == 'Q') { b[0] = 0x66; b[1] = 0x90; b[2] = 0xB8;
                    memcpy(b + 3, &i, 4); b[7] = 0xC3; return 8; }
#elif defined(__aarch64__)
    uint32_t movz = 0x52800000u | ((imm & 0xffff) << 5);
    uint32_t ret  = 0xD65F03C0u;
    uint32_t zero = 0x52800000u;
    uint32_t add  = 0x11000000u | ((imm & 0xfff) << 10);
    /* A: movz w0,#imm ; ret */
    if (s == 'A') { memcpy(b, &movz, 4); memcpy(b + 4, &ret, 4); return 8; }
    /* B: movz w0,#0 ; add w0,w0,#imm ; ret */
    if (s == 'B') { memcpy(b, &zero, 4); memcpy(b + 4, &add, 4);
                    memcpy(b + 8, &ret, 4); return 12; }
#elif defined(__riscv)
    uint32_t li   = ((imm & 0x7ff) << 20) | 0x00000513u;  /* addi a0,x0,imm */
    uint32_t ret  = 0x00008067u;                          /* ret            */
    uint32_t zero = 0x00000513u;                          /* addi a0,x0,0   */
    uint32_t add  = ((imm & 0x7ff) << 20) | 0x00050513u;  /* addi a0,a0,imm */
    uint16_t cnop = 0x0001;                               /* c.nop  (2 B)   */
    uint32_t nop4 = 0x00000013u;                          /* nop    (4 B)   */
    if (s == 'A') { memcpy(b, &li, 4); memcpy(b + 4, &ret, 4); return 8; }
    if (s == 'B') { memcpy(b, &zero, 4); memcpy(b + 4, &add, 4);
                    memcpy(b + 8, &ret, 4); return 12; }
    /* P: c.nop ; c.nop ; addi a0,x0,imm ; ret            (4 insns, 12 bytes) */
    if (s == 'P') { memcpy(b, &cnop, 2); memcpy(b + 2, &cnop, 2);
                    memcpy(b + 4, &li, 4); memcpy(b + 8, &ret, 4); return 12; }
    /* Q: nop ; addi a0,x0,imm ; ret                      (3 insns, 12 bytes) */
    if (s == 'Q') { memcpy(b, &nop4, 4); memcpy(b + 4, &li, 4);
                    memcpy(b + 8, &ret, 4); return 12; }
#elif defined(__mips__)
    uint32_t ori   = 0x34020000u | (imm & 0xffff);        /* ori $v0,$0,imm */
    uint32_t jr    = 0x03E00008u;                         /* jr $ra         */
    uint32_t nop   = 0x00000000u;                         /* delay slot     */
    uint32_t zero  = 0x34020000u;                         /* ori $v0,$0,0   */
    uint32_t addiu = 0x24420000u | (imm & 0x7fff);        /* addiu $v0,$v0  */
    if (s == 'A') { memcpy(b, &ori, 4); memcpy(b + 4, &jr, 4);
                    memcpy(b + 8, &nop, 4); return 12; }
    if (s == 'B') { memcpy(b, &zero, 4); memcpy(b + 4, &addiu, 4);
                    memcpy(b + 8, &jr, 4); memcpy(b + 12, &nop, 4); return 16; }
#else
#error "unsupported ISA"
#endif
    return 0;
}

int main(void)
{
    uint8_t *code = (uint8_t *)mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) return 2;
    typedef int (*fn_t)(void);
    fn_t fn = (fn_t)(void *)code;
    const char *shapes = SMC_SHAPES;
    static const uint32_t imms[] = SMC_IMMS;
    uint8_t body[16];
    volatile int acc = 0;
    long want = 0;

    for (int i = 0; shapes[i]; i++) {
        if (!enc(body, shapes[i], imms[i])) return 3;   /* shape unencodable */
        /* Always write the whole 16-byte body so a shorter shape leaves no
         * stale tail: each state's page content is a pure function of its
         * (shape, immediate), which is what the content signature keys on. */
        memcpy(code, body, 16);
        __builtin___clear_cache((char *)code, (char *)code + 16);
        if (SMC_FIRST_ONLY && i > 0) continue;
        for (int r = 0; r < SMC_EXEC_EACH; r++) { acc += fn(); want += imms[i]; }
    }
    return (acc == want) ? 0 : 1;
}
"""


# ---------------------------------------------------------------------------
# Python mirror of the C encoder: the per-instruction byte images of a shape.
# A revision's identity at the SMC pc is exactly this list.
# ---------------------------------------------------------------------------

def shape_insns(isa: str, shape: str, imm: int) -> list:
    """The instruction-by-instruction raw bytes of @shape encoded for @imm —
    the per-ISA mirror of the C ``enc()``.  Returns [] when @isa cannot encode
    @shape (the boundary-shift shapes on a fixed-width ISA)."""
    def w32(v):
        return (v & 0xFFFFFFFF).to_bytes(4, "little")

    if isa == "x86_64":
        i4 = (imm & 0xFFFFFFFF).to_bytes(4, "little")
        if shape == "A":
            return [bytes([0xB8]) + i4, bytes([0xC3])]
        if shape == "B":
            return [bytes([0x31, 0xC0]), bytes([0x05]) + i4, bytes([0xC3])]
        if shape == "P":
            return [bytes([0x90]), bytes([0x90]),
                    bytes([0xB8]) + i4, bytes([0xC3])]
        if shape == "Q":
            return [bytes([0x66, 0x90]), bytes([0xB8]) + i4, bytes([0xC3])]
    elif isa == "aarch64":
        movz = w32(0x52800000 | ((imm & 0xFFFF) << 5))
        ret = w32(0xD65F03C0)
        if shape == "A":
            return [movz, ret]
        if shape == "B":
            return [w32(0x52800000),
                    w32(0x11000000 | ((imm & 0xFFF) << 10)), ret]
    elif isa == "riscv64":
        li = w32(((imm & 0x7FF) << 20) | 0x00000513)
        ret = w32(0x00008067)
        if shape == "A":
            return [li, ret]
        if shape == "B":
            return [w32(0x00000513),
                    w32(((imm & 0x7FF) << 20) | 0x00050513), ret]
        if shape == "P":
            cnop = (0x0001).to_bytes(2, "little")
            return [cnop, cnop, li, ret]
        if shape == "Q":
            return [w32(0x00000013), li, ret]
    elif isa == "mipsel":
        jr, nop = w32(0x03E00008), w32(0x00000000)
        if shape == "A":
            return [w32(0x34020000 | (imm & 0xFFFF)), jr, nop]
        if shape == "B":
            return [w32(0x34020000),
                    w32(0x24420000 | (imm & 0x7FFF)), jr, nop]
    else:
        raise ValueError(f"unknown isa {isa}")
    return []


def isa_supports(isa: str, family: str) -> bool:
    """True when @isa can encode every shape @family writes."""
    return all(s in ISA_SHAPES.get(isa, "") for s in FAMILIES[family]["shapes"])


def state_key(isa: str, shape: str, imm: int) -> tuple:
    """Hashable identity of one written program-text state."""
    return tuple(shape_insns(isa, shape, imm))


def expected_structure(isa: str, family: str) -> tuple:
    """Model the plugin's revision behaviour for @isa/@family from first
    principles.  Returns (retained_states, body_runs):

      retained_states — the distinct states that end up SERIALISED as
                        templates at the SMC pc, in mint order;
      body_runs       — the states the body's ENTRY records must reference,
                        run-length collapsed, in execution order.

    Mirrors ``TemplateStore::resolve_true_bb``: a state already seen reuses its
    revision id, a new state mints unless the per-pc cap is reached, and a
    capped state keeps referencing whichever revision is live."""
    fam = FAMILIES[family]
    cap = fam.get("cap")
    retained: list = []
    runs: list = []
    live = None
    for i, shape in enumerate(fam["shapes"]):
        key = state_key(isa, shape, fam["imms"][i])
        if fam.get("first_only") and i > 0:
            continue                       # written but never re-executed
        if key in retained:
            live = key                     # content-signature id reuse
        elif cap is not None and len(retained) >= cap:
            pass                           # capped: keeps the live revision
        else:
            retained.append(key)
            live = key
        if not runs or runs[-1] != live:
            runs.append(live)
    return retained, runs


# ---------------------------------------------------------------------------
# Build / trace
# ---------------------------------------------------------------------------

def build_program(isa: str, family: str, work_dir: Path,
                  compilers: dict) -> Path | None:
    """Write and compile the SMC C program for @isa/@family.  Returns the
    binary path, or None if the ISA's compiler is unavailable or the ISA
    cannot encode one of the family's shapes."""
    cc = compilers.get(isa)
    if not cc:
        return None
    from shutil import which
    if which(cc) is None:
        return None
    if not isa_supports(isa, family):
        return None
    fam = FAMILIES[family]
    work_dir.mkdir(parents=True, exist_ok=True)
    src = work_dir / f"smc_{family}_{isa}.c"
    src.write_text(C_SOURCE)
    out = work_dir / f"smc_{family}_{isa}"
    imms = ", ".join(f"0x{v:x}" for v in fam["imms"])
    cmd = [cc, "-O0", "-static",
           f'-DSMC_SHAPES="{fam["shapes"]}"',
           f"-DSMC_IMMS={{{imms}}}",
           f"-DSMC_FIRST_ONLY={1 if fam.get('first_only') else 0}",
           f"-DSMC_EXEC_EACH={EXEC_EACH}",
           "-o", str(out), str(src)]
    if subprocess.call(cmd) != 0:
        return None
    return out


def trace_program(binary: Path, plugin: Path, qemu: Path, out_base: Path,
                  family: str) -> Path | None:
    """Run @binary under @qemu with the plugin.  A family carrying a ``cap``
    forces that revision cap via CST_SMC_REVISION_CAP.  Returns the .cst path
    or None."""
    import os
    env = dict(os.environ)
    cap = FAMILIES[family].get("cap")
    if cap is not None:
        env["CST_SMC_REVISION_CAP"] = str(cap)
    opts = f"outfile={out_base},wpdepth=16"
    rc = subprocess.call([str(qemu), "-plugin", f"{plugin},{opts}",
                          str(binary)], env=env)
    cst = Path(f"{out_base}.cst")
    if rc != 0 or not cst.is_file():
        return None
    return cst


def plugin_smc_stats(out_base: Path) -> dict:
    """Parse the plugin's ``<outfile>.stats.log`` SMC counters.  Returns {} if
    the sidecar is absent."""
    log = Path(f"{out_base}.stats.log")
    if not log.is_file():
        return {}
    wanted = {
        "SMC revisions minted": "minted",
        "SMC revision id reuses": "reuses",
        "SMC revision overflow events": "overflow_events",
        "SMC extent-only artifacts": "extent_artifacts",
    }
    out: dict = {}
    for line in log.read_text(errors="replace").splitlines():
        for name, key in wanted.items():
            if line.startswith(name):
                tail = line[len(name):].strip()
                if tail.isdigit():
                    out[key] = int(tail)
    return out


# ---------------------------------------------------------------------------
# Oracle
# ---------------------------------------------------------------------------

def template_state(t) -> tuple:
    """The state key a decoded template carries: its per-instruction bytes."""
    return tuple(bytes(i.get("raw_bytes") or b"")
                 for i in (t.get("insns") or []))


def smc_templates(isa: str, family: str, templates: list) -> tuple:
    """Locate the self-modified block's templates among @templates, grouped by
    start_pc: the pc carrying the most templates whose instruction bytes match
    one of the family's written states.  Returns (start_pc, [templates...]
    sorted by template_id) or (None, [])."""
    fam = FAMILIES[family]
    wanted = {state_key(isa, s, fam["imms"][i])
              for i, s in enumerate(fam["shapes"])}
    by_pc: dict = {}
    for t in templates:
        if not t.get("insns"):
            continue
        if template_state(t) in wanted:
            by_pc.setdefault(int(t["start_pc"]), []).append(t)
    if not by_pc:
        return None, []
    pc = max(by_pc, key=lambda p: len(by_pc[p]))
    return pc, sorted(by_pc[pc], key=lambda t: int(t["template_id"]))


def _fmt(states) -> str:
    return "[" + ", ".join("/".join(b.hex() for b in s) for s in states) + "]"


def check_family(isa: str, family: str, templates: list,
                 entries: list | None = None) -> tuple:
    """Assert the SMC revision structure for @isa/@family: the exact number of
    revisions serialised at the self-modified pc, that each is byte-correct for
    one of the family's written states, that they are byte-distinct, and — when
    @entries is supplied — that the body's template references resolve to the
    right revision at every position.  Returns (ok: bool, detail: str)."""
    want_states, want_runs = expected_structure(isa, family)
    expect = FAMILIES[family]["revisions"]
    pc, tmpls = smc_templates(isa, family, templates)
    if pc is None:
        return False, "SMC block not found in templates"

    got = len(tmpls)
    if got != expect:
        return False, (f"pc=0x{pc:x}: {got} revisions, expected {expect} "
                       f"(ids={[t['template_id'] for t in tmpls]})")

    # Every serialised revision must be byte-correct for a written state, and
    # the retained set must be exactly the states the model says survive.
    got_states = [template_state(t) for t in tmpls]
    if len(set(got_states)) != got:
        return False, (f"pc=0x{pc:x}: revisions are not byte-distinct "
                       f"{_fmt(got_states)}")
    if set(got_states) != set(want_states):
        return False, (f"pc=0x{pc:x}: retained revisions {_fmt(got_states)} "
                       f"!= expected {_fmt(want_states)}")

    detail = (f"pc=0x{pc:x}: {got} revision(s) "
              f"ids={[t['template_id'] for t in tmpls]} "
              f"insn_counts={[len(s) for s in got_states]}")

    if entries is None:
        return True, detail + " OK"

    # Version-aware body check: the ENTRY records at this pc, run-length
    # collapsed, must name the revision that was live at each position.
    by_id = {int(t["template_id"]): template_state(t) for t in tmpls}
    seen_runs: list = []
    for e in entries:
        st = by_id.get(int(e["template_id"]))
        if st is None:
            continue
        if not seen_runs or seen_runs[-1] != st:
            seen_runs.append(st)
    if seen_runs != want_runs:
        return False, (f"pc=0x{pc:x}: body references {_fmt(seen_runs)} "
                       f"!= expected {_fmt(want_runs)}")
    return True, detail + f" body_runs={len(seen_runs)} OK"


# ---------------------------------------------------------------------------
# Host-side discriminator truth table
# ---------------------------------------------------------------------------
#
# The shape-agnostic discriminator's EXTENT_ONLY branch — byte-identical
# overlap, different extent — is not reachable from a guest program: the fault
# machinery merges an interrupted chain back into a whole BB and the wrong-path
# walker commits only sealed BBs.  Drive the decision function directly instead,
# so the negative control (an extent artifact must NOT mint) is proved rather
# than assumed, alongside every positive branch.

DISCRIMINATOR_CC = r"""
#include <cstdio>
#include <cstring>
#include <vector>
#include "champsim_tracer_smc_match.h"

static const uint32_t STRIDE = 16;

struct Block {
    std::vector<uint64_t> pcs;
    std::vector<uint8_t>  sizes;
    std::vector<uint8_t>  bytes;
    /* Append one instruction at @pc with @n raw bytes, zero-padded to the
     * fixed stride exactly as the plugin's template builder does. */
    void add(uint64_t pc, const uint8_t *raw, uint8_t n) {
        pcs.push_back(pc);
        sizes.push_back(n);
        size_t off = bytes.size();
        bytes.resize(off + STRIDE, 0);
        memcpy(&bytes[off], raw, n);
    }
    uint32_t n() const { return (uint32_t)pcs.size(); }
};

/* Lay out a contiguous run of instructions starting at @base: each entry of
 * @spec is "<len>:<first byte>", so the PCs follow the sizes exactly as a real
 * true BB's do. */
static Block lay(uint64_t base, const std::vector<std::pair<uint8_t, uint8_t>> &spec)
{
    Block b;
    uint64_t pc = base;
    for (auto &s : spec) {
        uint8_t raw[16] = {0};
        for (uint8_t k = 0; k < s.first; k++) raw[k] = (uint8_t)(s.second + k);
        b.add(pc, raw, s.first);
        pc += s.first;
    }
    return b;
}

static int fails = 0;

static void expect(const char *name, const Block &oldb, const Block &newb,
                   BBMatch want)
{
    BBMatch got = cst_classify_bb_match(
        oldb.n(), oldb.pcs.data(), oldb.sizes.data(), oldb.bytes.data(),
        newb.n(), newb.pcs.data(), newb.sizes.data(), newb.bytes.data(),
        STRIDE);
    const char *names[] = { "EXACT", "SMC", "EXTENT_ONLY" };
    printf("%-28s %-12s %s\n", name, names[(int)got],
           got == want ? "OK" : "FAIL");
    if (got != want) { fails++; printf("   wanted %s\n", names[(int)want]); }
}

int main(void)
{
    const uint64_t B = 0x400000;

    /* --- unchanged code ------------------------------------------------- */
    expect("identical",
           lay(B, {{4,1},{4,9},{2,3}}), lay(B, {{4,1},{4,9},{2,3}}),
           BBMatch::EXACT);

    /* --- self-modification that KEEPS the boundaries -------------------- */
    expect("inplace_byte_patch",
           lay(B, {{4,1},{4,9},{2,3}}), lay(B, {{4,1},{4,0x40},{2,3}}),
           BBMatch::SMC);
    expect("inplace_patch_at_0",
           lay(B, {{4,1},{4,9}}), lay(B, {{4,0x70},{4,9}}),
           BBMatch::SMC);

    /* --- self-modification that MOVES the boundaries -------------------- */
    expect("grow_insn_count",
           lay(B, {{4,1},{4,9}}), lay(B, {{2,0x20},{2,0x30},{4,9}}),
           BBMatch::SMC);
    expect("shrink_insn_count",
           lay(B, {{2,0x20},{2,0x30},{4,9}}), lay(B, {{4,1},{4,9}}),
           BBMatch::SMC);
    expect("boundary_shift_same_len",
           lay(B, {{1,0x90},{1,0x90},{4,1}}), lay(B, {{2,0x66},{4,1}}),
           BBMatch::SMC);
    expect("boundary_shift_late",
           lay(B, {{4,1},{4,9},{4,0x11}}), lay(B, {{4,1},{2,0x50},{2,0x60},{4,0x11}}),
           BBMatch::SMC);
    expect("same_image_size_differs",
           lay(B, {{4,1},{4,9}}), lay(B, {{3,1},{4,9}}),
           BBMatch::SMC);

    /* --- extent artifacts: byte-identical overlap, different extent ------ */
    /* THE NEGATIVE CONTROL: none of these may mint a revision. */
    {
        Block shortb = lay(B, {{4,1},{4,9}});
        Block longb  = lay(B, {{4,1},{4,9},{4,0x11},{2,3}});
        expect("extent_longer",  shortb, longb,  BBMatch::EXTENT_ONLY);
        expect("extent_shorter", longb,  shortb, BBMatch::EXTENT_ONLY);
    }
    {
        /* Re-anchored start carrying the same bytes: an artifact, not SMC. */
        Block a = lay(B,       {{4,1},{4,9}});
        Block b = lay(B + 0x8, {{4,1},{4,9}});
        expect("reanchored_same_bytes", a, b, BBMatch::EXTENT_ONLY);
    }
    {
        /* Re-anchored start carrying DIFFERENT bytes: self-modification. */
        Block a = lay(B,       {{4,1},{4,9}});
        Block b = lay(B + 0x8, {{4,0x55},{4,9}});
        expect("reanchored_diff_bytes", a, b, BBMatch::SMC);
    }
    {
        /* PC divergence past a byte-identical prefix (a non-contiguous
         * assembly, only reachable as an artifact). */
        Block a = lay(B, {{4,1},{4,9},{4,0x11}});
        Block b = lay(B, {{4,1},{4,9},{4,0x11}});
        b.pcs[2] += 0x100;
        expect("pc_divergence_same_bytes", a, b, BBMatch::EXTENT_ONLY);
    }

    printf("%s %d failure(s)\n", fails ? "FAILED" : "PASSED", fails);
    return fails ? 1 : 0;
}
"""


def run_discriminator_truth_table(work_dir: Path, plugin_dir: Path) -> tuple:
    """Compile and run the host-side truth table over
    ``champsim_tracer_smc_match.h``.  Returns (ok, detail)."""
    from shutil import which
    cc = "g++"
    if which(cc) is None:
        return True, "skip (no host g++)"
    work_dir.mkdir(parents=True, exist_ok=True)
    src = work_dir / "smc_discriminator.cc"
    src.write_text(DISCRIMINATOR_CC)
    binp = work_dir / "smc_discriminator"
    cmd = [cc, "-std=c++17", "-O1", f"-I{plugin_dir}", "-o", str(binp),
           str(src)]
    if subprocess.call(cmd) != 0:
        return False, "truth-table build failed"
    p = subprocess.run([str(binp)], capture_output=True, text=True)
    out = (p.stdout or "").strip().splitlines()
    cases = [ln for ln in out if ln.endswith(" OK") or ln.endswith(" FAIL")]
    if p.returncode != 0:
        bad = [ln for ln in cases if ln.endswith(" FAIL")]
        return False, f"{len(bad)}/{len(cases)} discriminator cases FAIL: {bad}"
    return True, (f"{len(cases)}/{len(cases)} discriminator cases OK "
                  f"(EXACT / SMC any-shape / EXTENT_ONLY negative control)")


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------

def run_families(build_dir: Path, work_root: Path, plugin: Path,
                 compilers: dict, cflags_unused=None) -> tuple:
    """Drive every family across every ISA, plus the host-side discriminator
    truth table.  Returns (all_ok, subchecks:list).  Each subcheck is a dict
    {name, ok, detail} for the features-tier report."""
    from . import validator as V

    subs = []
    all_ok = True

    plugin_dir = Path(__file__).resolve().parents[2]
    ok, detail = run_discriminator_truth_table(work_root / "discriminator",
                                               plugin_dir)
    all_ok = all_ok and ok
    subs.append({"name": "discriminator", "ok": ok, "detail": detail})

    for isa in ("x86_64", "aarch64", "riscv64", "mipsel"):
        qemu = build_dir / f"qemu-{isa}"
        if not qemu.exists():
            subs.append({"name": isa, "ok": True, "detail": "skip (no qemu)"})
            continue
        for family in FAMILY_ORDER:
            name = f"{isa}/{family}"
            if not isa_supports(isa, family):
                subs.append({"name": name, "ok": True,
                             "detail": "skip (ISA cannot encode the shape: "
                                       "boundary shift needs a variable-width "
                                       "encoding)"})
                continue
            d = work_root / f"smc_{isa}"
            binp = build_program(isa, family, d, compilers)
            if binp is None:
                subs.append({"name": name, "ok": True,
                             "detail": "skip (no compiler)"})
                continue
            out_base = d / f"smc_{family}_{isa}_trace"
            cst = trace_program(binp, plugin, qemu, out_base, family)
            if cst is None:
                subs.append({"name": name, "ok": False,
                             "detail": "trace failed"})
                all_ok = False
                continue
            _m, templates, entries = \
                V._load_decoder().decode_champsim_tracer(cst)
            ok, detail = check_family(isa, family, templates, entries)
            stats = plugin_smc_stats(out_base)
            if ok and stats:
                want_mints = max(0, FAMILIES[family]["revisions"] - 1)
                if family == "cap_overflow":
                    want_mints = FAMILIES[family]["cap"] - 1
                if stats.get("minted", want_mints) != want_mints:
                    ok = False
                    detail += (f" -- plugin minted {stats['minted']}, "
                               f"expected {want_mints}")
                else:
                    detail += (f" minted={stats.get('minted')} "
                               f"extent_artifacts="
                               f"{stats.get('extent_artifacts')}")
            all_ok = all_ok and ok
            subs.append({"name": name, "ok": ok, "detail": detail})
    return all_ok, subs


# ---------------------------------------------------------------------------
# Mutation-tier support: SMC substrates + a version-aware revision-bytes
# oracle the mutation runner drives (see _mutation.py).
# ---------------------------------------------------------------------------

# Families the mutation tier needs a traced substrate for.
MUTATION_SUBSTRATES = ("flip_flop", "grow")


def mutation_substrate(build_dir: Path, work_root: Path, compilers: dict,
                       plugin: Path, family: str = "flip_flop") -> dict | None:
    """Build + trace an x86_64 SMC substrate for @family (>=2 revisions at one
    pc) for the mutation tier.  Returns {isa, family, pc, cst, templates} or
    None if unavailable."""
    from . import validator as V

    isa = "x86_64"
    d = work_root / f"smc_substrate_{family}"
    binp = build_program(isa, family, d, compilers)
    if binp is None:
        return None
    qemu = build_dir / f"qemu-{isa}"
    if not qemu.exists():
        return None
    cst = trace_program(binp, plugin, qemu, d / "smc_sub", family)
    if cst is None:
        return None
    _m, templates, _e = V._load_decoder().decode_champsim_tracer(cst)
    pc, tmpls = smc_templates(isa, family, templates)
    if pc is None or len(tmpls) < 2:
        return None
    return {"isa": isa, "family": family, "pc": pc,
            "cst": str(cst), "templates": templates}


def mutation_substrates(build_dir: Path, work_root: Path, compilers: dict,
                        plugin: Path, families=MUTATION_SUBSTRATES) -> dict:
    """Build every substrate the mutation catalogue asks for, keyed by family.
    A family that cannot be built is simply absent (its mutations skip)."""
    out: dict = {}
    for fam in families:
        sub = mutation_substrate(build_dir, work_root, compilers, plugin, fam)
        if sub is not None:
            out[fam] = sub
    return out


def check_substrate(templates: list, isa: str, family: str) -> list:
    """Version-aware SMC revision-bytes oracle: every template at the SMC pc
    must carry the exact instruction bytes of one of the family's written
    states, and the retained revisions must be byte-distinct with the expected
    count.  Returns a list of Issue-shaped tuples (check, severity, message) —
    empty on a clean trace, non-empty when a revision's bytes are corrupted."""
    ok, detail = check_family(isa, family, templates)
    if ok:
        return []
    return [("smc_revision_bytes", "error", detail)]


# ---------------------------------------------------------------------------
# System-mode family: a marker-emitting SMC program that ASID-pins itself and
# self-modifies inside the marker window.  Proves the (asid_root, start_pc)
# revision path under system emulation (smc_plan.md §4.3).  x86_64 only (the
# marker sequence and the RWX self-patch are encoded for x86 here).
# ---------------------------------------------------------------------------

C_SOURCE_MARKER = r"""
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>

/* Three identical `mov $imm,%eax` in a row = one ChampSim marker sequence. */
#define MARKER(imm) __asm__ __volatile__( \
    "mov $" #imm ", %%eax\n\t" \
    "mov $" #imm ", %%eax\n\t" \
    "mov $" #imm ", %%eax\n\t" \
    : : : "eax")

/* Shape A: mov $imm,%eax ; ret.   Shape B: xor %eax,%eax ; add $imm,%eax ; ret
 * — one instruction MORE at the same start_pc, so the system-mode seam is
 * proved on a SHAPE-CHANGING rewrite, not only an in-place byte patch. */
static unsigned encode_body(uint8_t *buf, int shape, uint32_t imm)
{
    memset(buf, 0, 16);
    if (shape == 0) { buf[0] = 0xB8; memcpy(buf + 1, &imm, 4); buf[5] = 0xC3;
                      return 6; }
    buf[0] = 0x31; buf[1] = 0xC0; buf[2] = 0x05;
    memcpy(buf + 3, &imm, 4); buf[7] = 0xC3;
    return 8;
}

int main(void)
{
    MARKER(0x43535401);                        /* START: open window + pin ASID */
    uint8_t *code = (uint8_t *)mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    volatile int acc = 0;
    if (code != MAP_FAILED) {
        typedef int (*fn_t)(void);
        fn_t fn = (fn_t)(void *)code;
        uint8_t body[16];
        for (int i = 0; i < 2; i++) {
            encode_body(body, i, 0x101);
            memcpy(code, body, 16);
            __builtin___clear_cache((char *)code, (char *)code + 16);
            for (int r = 0; r < 4; r++) acc += fn();
        }
    }
    MARKER(0x43535402);                        /* END: close the window */
    return (acc != 0) ? 0 : 1;
}
"""


def run_system_family(build_dir: Path, work_root: Path, plugin: Path,
                      compilers: dict) -> tuple:
    """Boot qemu-system-x86_64 with a marker-emitting SMC program staged into
    the initramfs; assert it mints exactly 2 revisions at the self-modified pc
    under the pinned ASID, across a SHAPE-CHANGING rewrite (2 insns -> 3).
    Returns (all_ok, subchecks).  Skips cleanly if the x86 system fixtures /
    qemu-system binary are absent."""
    import subprocess
    from . import _system as SYS
    from . import validator as V

    isa = "x86_64"
    subs = []
    cc = compilers.get(isa)
    qemu_sys = build_dir / SYS.ISA_QEMU_SYSTEM[isa]
    kernel = SYS.default_kernel(isa)
    base_root = SYS.default_root(isa)
    if not cc or not qemu_sys.exists() or not kernel.exists() \
            or not base_root.exists():
        subs.append({"name": f"{isa}/system", "ok": True,
                     "detail": "skip (system fixtures/compiler absent)"})
        return True, subs

    work_root.mkdir(parents=True, exist_ok=True)
    src = work_root / "smc_sys.c"
    src.write_text(C_SOURCE_MARKER)
    binp = work_root / "smc_sys"
    if subprocess.call([cc, "-O0", "-static", "-o", str(binp), str(src)]) != 0:
        subs.append({"name": f"{isa}/system", "ok": True,
                     "detail": "skip (build failed)"})
        return True, subs

    stage = work_root / "sysstage"
    stage.mkdir(parents=True, exist_ok=True)
    initrd = SYS.stage_initramfs(base_root, binp, stage)
    out_base = work_root / "smc_sys_trace"
    opts = (f"outfile={out_base},wpdepth=16,"
            f"trace_window=marker:simulation=2000000,memdata=1")
    cmd = SYS.system_qemu_cmd(qemu_sys, kernel, initrd, plugin, opts,
                              mem="512M", isa=isa, smp=1)
    log = Path(f"{out_base}.console.log")
    try:
        rc = subprocess.call(cmd, stdout=open(log, "w"),
                             stderr=subprocess.STDOUT, timeout=300)
    except subprocess.TimeoutExpired:
        subs.append({"name": f"{isa}/system", "ok": False,
                     "detail": "boot timed out"})
        return False, subs
    cst = Path(f"{out_base}.cst")
    if rc != 0 or not cst.is_file():
        subs.append({"name": f"{isa}/system", "ok": False,
                     "detail": f"boot rc={rc} / no trace"})
        return False, subs

    _m, templates, _e = V._load_decoder().decode_champsim_tracer(cst)
    # The marker program rewrites shape A into shape B at one pc: the `grow`
    # family's structure (2 revisions, the second one instruction longer).
    ok, detail = check_family(isa, "grow", templates)
    subs.append({"name": f"{isa}/system", "ok": ok,
                 "detail": f"(marker-window, pinned ASID, shape-changing) "
                           f"{detail}"})
    return ok, subs
