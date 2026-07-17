"""End-to-end regression guard for the wrong-path VALID-PTE-but-TLB-COLD
fetch policy (system mode).

Maintainer policy (the invariant this test locks):

  On a mispredicted (wrong) path, a speculative instruction fetch of a code
  page that has a VALID translation but is merely not iTLB-resident (a TLB
  miss that raises no fault) must do the page-table WALK, fill the TLB, and
  CAPTURE the block with its REAL instruction bytes.  Only a fetch with NO
  valid translation -- one that would demand-page an absent page (invoke the
  OS fault handler) -- terminates the excursion as translation-unavailable.

  The discriminator is a page-table walk that would demand-page, NOT mere
  TLB-coldness: a probe=true walk of an already-mapped page is benign (real
  hardware walks speculatively); only allocating an absent page is the
  forbidden speculative side effect.

The invariant only has teeth in SYSTEM mode: qemu-user has no softmmu TLB
(page_get_flags answers directly), so there is no cold-TLB state to miss and
the wrong-path fetch of a mapped page is unconditional.  The test therefore
boots a freestanding x86-64 payload under qemu-system-x86_64 with
trace_window=marker and asserts, from ONE trace:

  POSITIVE (valid-PTE, TLB-cold  -> CAPTURE real bytes)
     The payload KERNEL-touches a distinct code page (`cold_mapped`, its own
     4 KiB page holding a distinctive `mov $0xc0decafe`) via write(2), whose
     copy_from_user faults the PTE in from KERNEL context -- so its PTE is
     present while the USER addr_code TLB entry is never installed and the
     page stays genuinely iTLB-cold (a user data read would instead warm
     addr_code too, since tlb_set_page_full installs all compares).  An
     always-taken
     branch's wrong (fall-through) path then jumps into `cold_mapped`, which
     the CP never executes.  The wrong-path walker must WALK the present PTE,
     fill, and CAPTURE `cold_mapped` with its real bytes -- so the trace
     carries a WP block bearing the `0xc0decafe` immediate and NO
     translation-unavailable / fault marker.  (Because the CP never executes
     `cold_mapped`, the immediate can appear ONLY via a wrong-path capture.)

  NEGATIVE (no PTE -> TERMINATE)
     A second always-taken branch's wrong path jumps to a canonical VA that
     is never mapped (`0x5a5a00000000`).  The walker finds no PTE, declines
     to demand-page, and the WP block is marked TRANSLATION_UNAVAILABLE.

If a regression makes the wrong-path fetch treat a valid-but-TLB-cold page
as absent (terminate instead of capture), the POSITIVE assertion fails; if it
starts demand-paging genuinely-absent pages, the NEGATIVE assertion fails.

Point it at any build with ``CST_BUILD_DIR=/path/to/build``.  Skips cleanly
when the host lacks g++, qemu-system-x86_64, cst_decode, or the system-mode
kernel/rootfs fixtures.

Run standalone:
  python tests/test_wp_tlb_cold_capture.py
  CST_BUILD_DIR=/path/to/build python tests/test_wp_tlb_cold_capture.py
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Make the parent package importable when run standalone (for _system paths).
_PKG_PARENT = Path(__file__).resolve().parents[2]   # .../validator
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))


def _find_build_dir() -> Path:
    env = os.environ.get("CST_BUILD_DIR") or os.environ.get("BUILD_DIR")
    if env:
        return Path(env).resolve()
    repo = Path(__file__).resolve().parents[5]
    return repo / "build"


BUILD_DIR = _find_build_dir()
PLUGIN_SO = BUILD_DIR / "contrib" / "plugins" / "libchampsim_tracer.so"
CST_DECODE = BUILD_DIR / "contrib" / "plugins" / "cst_decode"
QEMU_SYS = BUILD_DIR / "qemu-system-x86_64"

WPDEPTH = 64
UNMAPPED_VA = 0x00005a5a00000000   # canonical, never mapped in a -nostdlib image
COLD_IMM = 0xC0DECAFE              # distinctive leading immediate at cold_mapped

# The freestanding payload.  Correct path: marker -> data-touch cold_mapped ->
# take both branches (skipping their fall-throughs) -> a little work -> end
# marker -> exit.  The wrong-path walker explores the two skipped fall-throughs.
COLDFETCH_ASM = f"""
.intel_syntax noprefix
.global _start
.text
_start:
    mov eax, 0x43535401
    mov eax, 0x43535401
    mov eax, 0x43535401

    mov rax, 1                     /* __NR_write: kernel copy_from_user */
    mov rdi, 1                     /* fd=1 (console) */
    lea rsi, [rip + cold_mapped]   /* demand-page cold_mapped from KERNEL ctx */
    mov rdx, 64
    syscall                        /* -> PTE present, user addr_code cold */

    jmp gate                       /* seal the marker block */
gate:
    mov rax, 1
    test rax, rax
    jnz pos_taken                  /* taken; wrong path = jmp cold_mapped */
    jmp cold_mapped
pos_taken:
    mov rax, 1
    test rax, rax
    jnz neg_taken                  /* taken; wrong path = jmp UNMAPPED_VA */
    movabs rbx, {UNMAPPED_VA}
    jmp rbx
neg_taken:
    mov rcx, 24
loop_top:
    add rax, rcx
    dec rcx
    jnz loop_top

    mov eax, 0x43535402
    mov eax, 0x43535402
    mov eax, 0x43535402

    mov rax, 60
    xor rdi, rdi
    syscall

.balign 4096
.global cold_mapped
cold_mapped:
    mov eax, 0x{COLD_IMM:08x}
    .rept 40
    add eax, 1
    .endr
cm_end:
    jmp cm_end
.size cold_mapped, .-cold_mapped
"""

_INIT = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst wp-tlb-cold guest: $(uname -r) ==="
/workload
echo "=== /workload exit=$? ; poweroff ==="
poweroff -f
"""


def _skip_reason() -> str | None:
    if not PLUGIN_SO.exists():
        return f"plugin not built: {PLUGIN_SO}"
    if not CST_DECODE.exists():
        return f"cst_decode not built: {CST_DECODE}"
    if not QEMU_SYS.exists():
        return f"qemu-system-x86_64 not built: {QEMU_SYS}"
    if shutil.which("g++") is None:
        return "g++ not in PATH"
    for tool in ("cpio", "gzip", "find"):
        if shutil.which(tool) is None:
            return f"{tool} not in PATH"
    try:
        from champsim_tracer_validator import _system as SYS
    except Exception as e:                                   # noqa: BLE001
        return f"cannot import _system for fixture paths: {e}"
    if not SYS.default_kernel("x86_64").exists():
        return f"system kernel fixture missing: {SYS.default_kernel('x86_64')}"
    if not SYS.default_root("x86_64").exists():
        return f"system rootfs fixture missing: {SYS.default_root('x86_64')}"
    return None


def _stage_and_boot(dd: Path) -> tuple[int, str]:
    """Build the payload, stage a rootfs, boot qemu-system, return
    (qemu_rc, cst_decode_stdout)."""
    from champsim_tracer_validator import _system as SYS

    src = dd / "coldfetch.s"
    exe = dd / "workload"
    src.write_text(COLDFETCH_ASM)
    subprocess.run(
        ["g++", "-static", "-nostdlib", "-nostartfiles", "-O1",
         "-fno-asynchronous-unwind-tables", "-fno-stack-protector",
         "-fno-optimize-sibling-calls", str(src), "-o", str(exe)],
        check=True, capture_output=True)

    # Stage the base rootfs + /workload + /init, repack the cpio.
    root = dd / "sysroot"
    root.mkdir()
    base = SYS.default_root("x86_64")
    subprocess.run(["cp", "-a", f"{base}/.", str(root)], check=True)
    shutil.copy(exe, root / "workload")
    (root / "workload").chmod(0o755)
    (root / "init").write_text(_INIT)
    (root / "init").chmod(0o755)
    cpio = dd / "rootfs.cpio.gz"
    with open(cpio, "wb") as out:
        find = subprocess.Popen(["find", "."], cwd=root, stdout=subprocess.PIPE)
        pack = subprocess.Popen(["cpio", "-H", "newc", "-o", "--quiet"],
                                cwd=root, stdin=find.stdout,
                                stdout=subprocess.PIPE)
        find.stdout.close()
        gz = subprocess.Popen(["gzip", "-c"], stdin=pack.stdout, stdout=out)
        pack.stdout.close()
        gz.communicate()
        find.wait()
        pack.wait()

    out_base = dd / "cf"
    plugin_opts = (f"outfile={out_base},wpdepth={WPDEPTH},"
                   f"trace_window=marker:simulation=200000,memdata=1,regdata=1")
    kernel = SYS.default_kernel("x86_64")
    cmd = [str(QEMU_SYS), "-kernel", str(kernel), "-initrd", str(cpio),
           "-append", "console=ttyS0 panic=-1 nopti",
           "-nographic", "-no-reboot", "-m", "512M", "-cpu", "max",
           "-plugin", f"{PLUGIN_SO},{plugin_opts}"]
    console = dd / "console.log"
    import signal as _signal
    with open(console, "w") as f:
        proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            rc = proc.wait(timeout=300)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), _signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            proc.wait()
            rc = 124

    cst = Path(f"{out_base}.cst")
    if not cst.exists():
        ctext = console.read_text(errors="replace") if console.exists() else ""
        raise AssertionError(f"boot produced no trace (qemu_rc={rc}); "
                             f"console tail:\n{ctext[-800:]}")
    dec = subprocess.run([str(CST_DECODE), str(cst)],
                         check=True, capture_output=True, text=True)
    return rc, dec.stdout


# Lines that decode a captured wrong-path instruction; the block-level status
# suffix (TRANSLATION_UNAVAILABLE / FAULT) rides on the same line.
_COLD_LINE = re.compile(rf"mov\s+\$0x{COLD_IMM:08x}\b", re.IGNORECASE)


def _run() -> tuple[list[str], list[str]]:
    with tempfile.TemporaryDirectory(prefix="cst_wptlb_") as d:
        _rc, out = _stage_and_boot(Path(d))
    lines = out.splitlines()
    cold_lines = [ln for ln in lines if _COLD_LINE.search(ln)]
    unavail_lines = [ln for ln in lines
                     if "TRANSLATION_UNAVAILABLE" in ln
                     and f"0x{UNMAPPED_VA:012x}" in ln.lower()]
    return cold_lines, unavail_lines


class WpTlbColdCapture(unittest.TestCase):
    def test_valid_pte_cold_page_is_captured_and_unmapped_terminates(self):
        reason = _skip_reason()
        if reason:
            raise unittest.SkipTest(reason)
        cold_lines, unavail_lines = _run()

        # POSITIVE: the valid-but-TLB-cold page was CAPTURED with real bytes.
        self.assertTrue(cold_lines, (
            "wrong-path fetch of a valid-PTE but iTLB-cold code page was NOT "
            f"captured: no WP instruction bearing the 0x{COLD_IMM:08x} "
            "immediate appears in the trace.  The walker must walk the present "
            "PTE, fill, and capture the block with real bytes -- a TLB miss on "
            "a mapped page is not translation-unavailable."))
        bad = [ln for ln in cold_lines
               if "TRANSLATION_UNAVAILABLE" in ln or "FAULT" in ln]
        self.assertFalse(bad, (
            "the valid-PTE cold-page capture is mismarked as unavailable/"
            f"faulted: {bad}"))

        # NEGATIVE: the genuinely-unmapped wrong-path target TERMINATED.
        self.assertTrue(unavail_lines, (
            f"wrong-path fetch of the unmapped VA 0x{UNMAPPED_VA:012x} did NOT "
            "terminate as TRANSLATION_UNAVAILABLE; a fetch with no valid "
            "translation must decline (no demand-paging), not capture."))


if __name__ == "__main__":
    r = _skip_reason()
    if r:
        print(f"SKIP test_wp_tlb_cold_capture: {r}")
        sys.exit(0)
    try:
        cold, unavail = _run()
        assert cold, "POSITIVE failed: no 0x%08x capture in WP" % COLD_IMM
        bad = [ln for ln in cold if "TRANSLATION_UNAVAILABLE" in ln
               or "FAULT" in ln]
        assert not bad, f"POSITIVE failed: capture mismarked: {bad}"
        assert unavail, ("NEGATIVE failed: unmapped 0x%012x not "
                         "TRANSLATION_UNAVAILABLE" % UNMAPPED_VA)
    except AssertionError as e:
        print(f"FAIL test_wp_tlb_cold_capture: {e}")
        sys.exit(1)
    print("PASS test_wp_tlb_cold_capture "
          f"(captured cold valid-PTE page 0x{COLD_IMM:08x}; "
          f"unmapped 0x{UNMAPPED_VA:012x} terminated)")
    sys.exit(0)
