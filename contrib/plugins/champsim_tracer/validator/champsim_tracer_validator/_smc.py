"""Self-modifying-code (SMC) workload family for the validator.

The plugin mints a new template *revision* (a fresh template_id at an already-
committed start_pc) when correct-path code re-executes with different bytes,
and reuses a prior revision's id when the guest restores a previously-seen
state.  See ``contrib/plugins/champsim_tracer/smc_plan.md``.

Each family here builds a tiny ``[load-immediate; return]`` function in an RWX
page, patches the immediate FIELD in place (identical insn PCs, changed bytes
= an in-place self-modification), syncs the icache, and re-executes.  Because
the whole word is re-encoded per state, the tracer sees a byte-changed block at
one start_pc:

  * ``patch_once``   — states A, B                 → exactly 2 revisions
  * ``flip_flop``    — states A, B, A, B           → exactly 2 revisions (the
                       returning A/B states reuse their original ids)
  * ``cap_overflow`` — 5 states with smc_revisions=2 → exactly 2 revisions kept
                       (minting stops; a LOUD warning fires)
  * ``write_no_exec``— write 4 states, execute only the first → 1 template,
                       no revision (writes that never re-execute never surface)

The oracle groups the decoded templates by start_pc, identifies the SMC block
by its ``load-immediate`` opcode, and asserts the exact revision structure
against the known patch states.  Self-contained: it does not go through the
diamond-CFG validator (the SMC program is not a diamond).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# Compile-time family selector fed to the C source via -DSMC_FAMILY.
FAMILY_ID = {
    "patch_once": 0,
    "flip_flop": 1,
    "cap_overflow": 2,
    "write_no_exec": 3,
}

# The four patch states each family cycles through (order matters).
FAMILY_STATES = {
    "patch_once": [0x101, 0x202],
    "flip_flop": [0x101, 0x202, 0x101, 0x202],
    "cap_overflow": [0x101, 0x202, 0x303, 0x404, 0x505],
    "write_no_exec": [0x101, 0x202, 0x303, 0x404],
}

# Expected number of DISTINCT template revisions serialised at the SMC pc.
FAMILY_EXPECT_REVISIONS = {
    "patch_once": 2,
    "flip_flop": 2,       # A/B/A/B folds to two ids, not four
    "cap_overflow": 2,    # capped at smc_revisions below
    "write_no_exec": 1,   # only the first state ever re-executes
}

# The revision cap forced (via CST_SMC_REVISION_CAP) for cap_overflow.
CAP_OVERFLOW_CAP = 2

C_SOURCE = r"""
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>

#ifndef SMC_FAMILY
#define SMC_FAMILY 0
#endif

static unsigned encode_body(uint8_t *buf, uint32_t imm)
{
#if defined(__x86_64__)
    uint32_t i = imm;
    buf[0] = 0xB8;                      /* mov eax, imm32 */
    memcpy(buf + 1, &i, 4);
    buf[5] = 0xC3;                      /* ret */
    return 6;
#elif defined(__aarch64__)
    uint32_t movz = 0x52800000u | ((imm & 0xffff) << 5); /* movz w0,#imm16 */
    uint32_t ret  = 0xD65F03C0u;                         /* ret */
    memcpy(buf + 0, &movz, 4);
    memcpy(buf + 4, &ret, 4);
    return 8;
#elif defined(__riscv)
    uint32_t addi = ((imm & 0x7ff) << 20) | 0x00000513u; /* addi a0,x0,imm12 */
    uint32_t ret  = 0x00008067u;                         /* ret */
    memcpy(buf + 0, &addi, 4);
    memcpy(buf + 4, &ret, 4);
    return 8;
#elif defined(__mips__)
    uint32_t ori = 0x34020000u | (imm & 0xffff);         /* ori $v0,$zero,imm16 */
    uint32_t jr  = 0x03E00008u;                          /* jr $ra */
    uint32_t nop = 0x00000000u;                          /* delay slot */
    memcpy(buf + 0, &ori, 4);
    memcpy(buf + 4, &jr, 4);
    memcpy(buf + 8, &nop, 4);
    return 12;
#else
#error "unsupported ISA"
#endif
}

int main(void)
{
    uint8_t *code = (uint8_t *)mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) return 2;
    typedef int (*fn_t)(void);
    fn_t fn = (fn_t)(void *)code;
    uint8_t body[16];
    volatile int acc = 0;

#if SMC_FAMILY == 0
    uint32_t states[] = { 0x101, 0x202 };
    int n = 2, exec_each = 3;
#elif SMC_FAMILY == 1
    uint32_t states[] = { 0x101, 0x202, 0x101, 0x202 };
    int n = 4, exec_each = 3;
#elif SMC_FAMILY == 2
    uint32_t states[] = { 0x101, 0x202, 0x303, 0x404, 0x505 };
    int n = 5, exec_each = 3;
#else
    uint32_t states[] = { 0x101, 0x202, 0x303, 0x404 };
    int n = 4, exec_each = 3;
#endif

    for (int i = 0; i < n; i++) {
        unsigned len = encode_body(body, states[i]);
        memcpy(code, body, len);
        __builtin___clear_cache((char *)code, (char *)code + len);
#if SMC_FAMILY == 3
        if (i == 0)
#endif
        for (int r = 0; r < exec_each; r++) acc += fn();
    }
    return (acc != 0) ? 0 : 1;
}
"""


def first_insn_bytes(isa: str, imm: int) -> bytes:
    """The bytes of the SMC block's FIRST (load-immediate) instruction for
    state @imm — the per-ISA mirror of encode_body's first word.  A revision's
    identity at the SMC pc is exactly this word."""
    if isa == "x86_64":
        return bytes([0xB8]) + (imm & 0xFFFFFFFF).to_bytes(4, "little")
    if isa == "aarch64":
        return (0x52800000 | ((imm & 0xFFFF) << 5)).to_bytes(4, "little")
    if isa == "riscv64":
        return (((imm & 0x7FF) << 20) | 0x00000513).to_bytes(4, "little")
    if isa == "mipsel":
        return (0x34020000 | (imm & 0xFFFF)).to_bytes(4, "little")
    raise ValueError(f"unknown isa {isa}")


def build_program(isa: str, family: str, work_dir: Path,
                  compilers: dict) -> Path | None:
    """Write and compile the SMC C program for @isa/@family.  Returns the
    binary path, or None if the ISA's compiler is unavailable."""
    cc = compilers.get(isa)
    if not cc:
        return None
    from shutil import which
    if which(cc) is None:
        return None
    work_dir.mkdir(parents=True, exist_ok=True)
    src = work_dir / f"smc_{family}_{isa}.c"
    src.write_text(C_SOURCE)
    out = work_dir / f"smc_{family}_{isa}"
    cmd = [cc, "-O0", "-static", f"-DSMC_FAMILY={FAMILY_ID[family]}",
           "-o", str(out), str(src)]
    if subprocess.call(cmd) != 0:
        return None
    return out


def trace_program(binary: Path, plugin: Path, qemu: Path, out_base: Path,
                  family: str) -> Path | None:
    """Run @binary under @qemu with the plugin.  cap_overflow forces a tiny
    revision cap via CST_SMC_REVISION_CAP.  Returns the .cst path or None."""
    import os
    env = dict(os.environ)
    if family == "cap_overflow":
        env["CST_SMC_REVISION_CAP"] = str(CAP_OVERFLOW_CAP)
    opts = f"outfile={out_base},wpdepth=16"
    rc = subprocess.call([str(qemu), "-plugin", f"{plugin},{opts}",
                          str(binary)], env=env)
    cst = Path(f"{out_base}.cst")
    if rc != 0 or not cst.is_file():
        return None
    return cst


def smc_templates(isa: str, family: str, templates: list) -> tuple:
    """Locate the SMC block's templates among @templates (those whose first
    insn is one of the family's known load-immediate words), grouped by
    start_pc.  Returns (start_pc, [templates...] sorted by template_id) or
    (None, []) if the block is not found."""
    wanted = {first_insn_bytes(isa, s) for s in FAMILY_STATES[family]}
    by_pc: dict = {}
    for t in templates:
        insns = t.get("insns") or []
        if not insns:
            continue
        rb = bytes(insns[0].get("raw_bytes") or b"")
        if rb in wanted:
            by_pc.setdefault(int(t["start_pc"]), []).append(t)
    if not by_pc:
        return None, []
    # The SMC block lives at exactly one pc; pick the pc carrying the most
    # matching templates (defensive against an unrelated coincidental match).
    pc = max(by_pc, key=lambda p: len(by_pc[p]))
    tmpls = sorted(by_pc[pc], key=lambda t: int(t["template_id"]))
    return pc, tmpls


def check_family(isa: str, family: str, templates: list) -> tuple:
    """Assert the SMC revision structure for @isa/@family against the known
    patch states.  Returns (ok: bool, detail: str)."""
    expect = FAMILY_EXPECT_REVISIONS[family]
    pc, tmpls = smc_templates(isa, family, templates)
    if pc is None:
        return False, "SMC block not found in templates"
    got = len(tmpls)
    if got != expect:
        return False, (f"pc=0x{pc:x}: {got} revisions, expected {expect} "
                       f"(ids={[t['template_id'] for t in tmpls]})")
    # Every serialised revision's first-insn word must be one of the known
    # states, and (patch_once/flip_flop) the retained set must be distinct.
    words = [bytes(t["insns"][0]["raw_bytes"]).hex() for t in tmpls]
    known = {first_insn_bytes(isa, s).hex() for s in FAMILY_STATES[family]}
    if any(w not in known for w in words):
        return False, f"pc=0x{pc:x}: a revision carries unknown bytes {words}"
    if len(set(words)) != got:
        return False, f"pc=0x{pc:x}: revisions are not byte-distinct {words}"
    return True, (f"pc=0x{pc:x}: {got} revision(s) "
                  f"ids={[t['template_id'] for t in tmpls]} OK")


def run_families(build_dir: Path, work_root: Path, plugin: Path,
                 compilers: dict, cflags_unused=None) -> tuple:
    """Drive every family across every ISA.  Returns (all_ok, subchecks:list).
    Each subcheck is a dict {name, ok, detail} for the features-tier report."""
    from . import validator as V

    subs = []
    all_ok = True
    for isa in ("x86_64", "aarch64", "riscv64", "mipsel"):
        qemu = build_dir / f"qemu-{isa}"
        if not qemu.exists():
            subs.append({"name": isa, "ok": True, "detail": "skip (no qemu)"})
            continue
        for family in ("patch_once", "flip_flop", "cap_overflow",
                       "write_no_exec"):
            d = work_root / f"smc_{isa}"
            binp = build_program(isa, family, d, compilers)
            if binp is None:
                subs.append({"name": f"{isa}/{family}", "ok": True,
                             "detail": "skip (no compiler)"})
                continue
            out_base = d / f"smc_{family}_{isa}_trace"
            cst = trace_program(binp, plugin, qemu, out_base, family)
            if cst is None:
                subs.append({"name": f"{isa}/{family}", "ok": False,
                             "detail": "trace failed"})
                all_ok = False
                continue
            _m, templates, _e = V._load_decoder().decode_champsim_tracer(cst)
            ok, detail = check_family(isa, family, templates)
            all_ok = all_ok and ok
            subs.append({"name": f"{isa}/{family}", "ok": ok, "detail": detail})
    return all_ok, subs


# ---------------------------------------------------------------------------
# Mutation-tier support: an SMC substrate + a version-aware revision-bytes
# oracle the mutation runner drives (see _mutation.py).
# ---------------------------------------------------------------------------

def mutation_substrate(build_dir: Path, work_root: Path, compilers: dict,
                       plugin: Path) -> dict | None:
    """Build + trace a flip-flop SMC substrate (x86_64: ≥2 revisions at one
    pc) for the mutation tier.  Returns {isa, family, templates_pc, cst,
    good_templates} or None if unavailable."""
    from . import validator as V

    isa, family = "x86_64", "flip_flop"
    d = work_root / "smc_substrate"
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

static unsigned encode_body(uint8_t *buf, uint32_t imm)
{
    uint32_t i = imm;
    buf[0] = 0xB8; memcpy(buf + 1, &i, 4); buf[5] = 0xC3;
    return 6;
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
        uint8_t body[8];
        uint32_t states[] = { 0x101, 0x202 };
        for (int i = 0; i < 2; i++) {
            unsigned len = encode_body(body, states[i]);
            memcpy(code, body, len);
            __builtin___clear_cache((char *)code, (char *)code + len);
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
    under the pinned ASID.  Returns (all_ok, subchecks).  Skips cleanly if the
    x86 system fixtures / qemu-system binary are absent."""
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
    # The marker program's self-modified block is the 2-state patch_once shape.
    ok, detail = check_family(isa, "patch_once", templates)
    subs.append({"name": f"{isa}/system", "ok": ok,
                 "detail": f"(marker-window, pinned ASID) {detail}"})
    return ok, subs


def check_substrate(templates: list, isa: str, family: str) -> list:
    """Version-aware SMC revision-bytes oracle: every template at the SMC pc
    must carry one of the family's known patch-state words, and the retained
    revisions must be byte-distinct with the expected count.  Returns a list
    of Issue-shaped tuples (check, severity, message) — empty on a clean
    trace, non-empty when a revision's bytes are corrupted."""
    ok, detail = check_family(isa, family, templates)
    if ok:
        return []
    return [("smc_revision_bytes", "error", detail)]
