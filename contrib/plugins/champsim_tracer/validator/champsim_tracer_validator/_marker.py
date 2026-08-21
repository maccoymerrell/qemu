#!/usr/bin/env python3
"""Marker-invariant gates for ``champsim_tracer_validator full``.

The trace marker (``champsim_marker.h``) is CST_MARKER_SEQ_LEN identical
immediate-loads in a row, and it is decided in the BYTES at translation
time: base QEMU's translator never ends a translation block inside a
magic-sequence prefix, so the whole sequence always arrives in one block,
and the plugin fires from a single ``memcmp`` of that block's delivered
bytes against the START/END patterns — no execution callback, no fence.
One block, one match, one event, at TRANSLATION (reach), not execution.

That design has exactly one invariant, and it has two directions:

    A COMPLETE MARKER SEQUENCE IS NEVER MISSED,
    AND AN INCOMPLETE ONE IS NEVER CLAIMED.

A corollary the model makes explicit: a jump that lands MID-sequence makes
the block start mid-sequence, so fewer than CST_MARKER_SEQ_LEN magic
instructions appear together and the whole-block match cannot form — such a
control flow is NOT a marker and must open no window (cell ``missable``).

Both directions are load-bearing and neither is visible in the wire.  A miss
produces no trace at all — a run that looks like a workload that simply never
opened its window — and a false claim produces a trace of whatever happened
to be running, which reads as a perfectly well-formed trace of the wrong
thing.  No structural oracle over the ``.cst`` file can see either one, so
they are asserted here, from the plugin's own startup/close narration and
from the presence or absence of a segment.

Three checks live here:

``features.marker_detection``
    Runs three purpose-built workloads per ISA (x86_64 and aarch64) under
    ``trace_window=marker``: a plain positive, an all-decoys negative, and a
    workload whose marker sequences are entered mid-sequence through a
    branch.  The negative and the mid-sequence workload are both "never
    claimed" directions — the mid-sequence branch makes the block start
    inside the sequence, so under whole-block matching fewer than
    CST_MARKER_SEQ_LEN magic instructions appear together and NO window may
    open; the plain positive is the "never missed" direction.

    aarch64 is not decoration.  On the fixed-width targets the START and END
    sequences are built from a two-instruction load pair whose second
    instruction — the high-half ``movk`` — is IDENTICAL between the two
    magics, so the terminating instruction of a START sequence and of an END
    sequence are the same 4 bytes.  Whole-block matching is what tells them
    apart — a decoy that presents a genuine marker tail is rejected only by
    comparing the whole sequence.  The chimera decoy is that exact shape.

``features.system_window_modes``
    In system mode the only window that names a process is the marker, so
    every other window mode is refused at startup.  Both directions of that
    refusal are proven: the four refused forms exit non-zero with the
    refusal on stderr, and the marker form gets past install.

Host-load hygiene: set ``CST_TASKSET`` to a taskset CPU list (e.g.
``24-47,96-119``) to pin every guest this module launches.  Unset — the
default — nothing is pinned, because a CPU list is a property of one host and
a validator that hard-codes one fails everywhere else.

Author: Maccoy Merrell.  SPDX-License-Identifier: GPL-2.0-or-later
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

from . import asm_blocks as B


# When this process started, near enough: ``_full`` imports this module while
# building its check table, before any check runs.  features.marker_corpus
# _clean uses it to sweep the stats.log corpus THIS RUN produced and leave
# older ones alone — `full`'s default work root is a directory operators reuse
# across runs, and it accumulates sidecars from every plugin build that ever
# wrote into it, including ones that predate the counters this check reads.
_RUN_START = time.time()
# Filesystem timestamp slack, in seconds.
_RUN_START_SLACK = 2.0


# The ISAs this module can emit a workload for.  Adding one means adding its
# row to _WORK/_EXIT/_JUMP/_SEP below and nothing else — the marker bytes
# themselves always come from asm_blocks' emitters, which read the contract
# out of champsim_marker.h.
MARKER_ISAS = ("x86_64", "aarch64")

# Big enough that a workload of a few thousand instructions closes on its END
# marker with the budget nowhere near spent; the check asserts that gap.
MARKER_SIM_BUDGET = 5_000_000
# Coverage must be at least this many times under budget for the close to be
# unambiguously an END-marker close rather than a budget close.
MARKER_BUDGET_HEADROOM = 10


def _outcome(status: str, detail: str = "", subchecks=None):
    """Build a :class:`_full.Outcome`.

    Imported lazily: ``_full`` registers the checks defined here, so a
    module-level import in this direction would close the cycle.
    """
    from ._full import Outcome
    return Outcome(status, detail, list(subchecks or []))


def _taskset_prefix() -> list:
    """The optional pin prefix (see CST_TASKSET in the module docstring)."""
    cpus = os.environ.get("CST_TASKSET", "").strip()
    if not cpus or not shutil.which("taskset"):
        return []
    return ["taskset", "-c", cpus]


# ===========================================================================
# workload assembly
# ===========================================================================
#
# The marker bytes come from asm_blocks.emit_trace_marker /
# emit_trace_marker_end, which build them from champsim_marker.h's contract —
# the same contract the plugin's detector compiles in.  Everything below is
# scaffolding around them: a counted loop for ordinary work, an exit syscall,
# an unconditional jump, and a separator instruction that is provably not part
# of any marker sequence.

def _work(isa: str, iters: int, tag: str) -> list:
    """A counted loop of @iters iterations: ordinary, marker-free work."""
    if isa == "x86_64":
        return [f"  mov ${iters}, %ecx",
                f"Lwork_{tag}:",
                "  add $1, %ebx",
                "  sub $1, %ecx",
                f"  jne Lwork_{tag}"]
    if isa == "aarch64":
        return [f"  mov w2, #{iters}",
                f"Lwork_{tag}:",
                "  add w1, w1, #1",
                "  subs w2, w2, #1",
                f"  b.ne Lwork_{tag}"]
    raise ValueError(f"_work: unsupported ISA {isa}")


def _exit(isa: str) -> list:
    """exit(0).  Placed after every decoy, so a clean guest exit status is
    proof that every decoy instruction retired."""
    if isa == "x86_64":
        return ["  mov $60, %rax", "  xor %rdi, %rdi", "  syscall"]
    if isa == "aarch64":
        return ["  mov x8, #93", "  mov x0, #0", "  svc #0"]
    raise ValueError(f"_exit: unsupported ISA {isa}")


def _jump(isa: str, label: str) -> list:
    if isa == "x86_64":
        return [f"  jmp {label}"]
    if isa == "aarch64":
        return [f"  b {label}"]
    raise ValueError(f"_jump: unsupported ISA {isa}")


def _sep(isa: str) -> list:
    """One instruction that cannot be any slot of any marker sequence, used
    to keep adjacent decoys from accidentally forming a complete one."""
    if isa == "x86_64":
        return ["  add $1, %ebx"]
    if isa == "aarch64":
        return ["  add w1, w1, #1"]
    raise ValueError(f"_sep: unsupported ISA {isa}")


def _seq_units(lines: list) -> list:
    """Split a marker sequence into its CST_MARKER_SEQ_LEN repeated units.

    x86 repeats a single ``mov``; the fixed-width ISAs repeat a two-
    instruction load pair.  The unit is derived from the emitted sequence and
    the sequence length in champsim_marker.h, so it tracks the contract
    rather than restating it.
    """
    seq_len = B._marker_contract()[2]
    if seq_len <= 0 or len(lines) % seq_len:
        raise RuntimeError(
            f"marker sequence of {len(lines)} instructions does not divide "
            f"into CST_MARKER_SEQ_LEN={seq_len} units")
    n = len(lines) // seq_len
    units = [lines[i * n:(i + 1) * n] for i in range(seq_len)]
    if any(u != units[0] for u in units):
        raise RuntimeError("marker sequence units are not identical — the "
                           "repeated-unit assumption in _seq_units is stale")
    return units


def _insns(lines: list) -> list:
    """The instruction lines of an assembly listing (labels, directives and
    comments dropped), normalised for comparison."""
    out = []
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#") or s.startswith("."):
            continue
        if s.endswith(":"):
            continue
        out.append(" ".join(s.split()))
    return out


def _contains_run(hay: list, needle: list) -> bool:
    if not needle or len(needle) > len(hay):
        return False
    return any(hay[i:i + len(needle)] == needle
               for i in range(len(hay) - len(needle) + 1))


def _prologue() -> list:
    return [".text", ".globl _start", ".type _start, @function", "_start:"]


def _epilogue() -> list:
    return [".size _start, .-_start"]


def wl_positive(isa: str) -> list:
    """(A) complete START, work, complete END, more work, exit.

    The START marker is emitted through :func:`emit_trace_marker_locked`, so
    the workload ``mlock``\\ s its marker page before running it — the model's
    residency requirement.  (User-mode detection needs no content re-read, so
    the lock is belt-and-suspenders here, but the same generated shape drives
    system-mode runs where it is load-bearing.)"""
    return (_prologue()
            + B.emit_trace_marker_locked(isa)
            + _work(isa, 2000, "a1")
            + B.emit_trace_marker_end(isa)
            + _work(isa, 500, "a2")
            + _exit(isa)
            + _epilogue())


def wl_negative(isa: str) -> list:
    """(B) no complete sequence anywhere — only decoys.

    Four shapes, each followed by a separator so no two decoys can abut into
    a complete sequence:

      * CST_MARKER_SEQ_LEN-1 adjacent START units;
      * one lone START unit;
      * one lone END unit;
      * the CHIMERA — the first CST_MARKER_SEQ_LEN-1 units of the START
        sequence immediately followed by the LAST unit of the END sequence.
        On the fixed-width ISAs the two sequences' terminating instruction is
        the same bytes, so this shape presents a genuine marker tail and can
        only be rejected by matching the WHOLE block against the pattern.
    """
    start_u = _seq_units(B.emit_trace_marker(isa))
    end_u = _seq_units(B.emit_trace_marker_end(isa))
    short = len(start_u) - 1                       # SEQ_LEN - 1

    decoys: list = []
    for group in ([u for unit in start_u[:short] for u in unit],   # 2 adjacent
                  list(start_u[0]),                                # lone START
                  list(end_u[0]),                                  # lone END
                  [u for unit in start_u[:short] for u in unit]    # chimera
                  + list(end_u[-1])):
        decoys += group + _sep(isa)

    return (_prologue()
            + _work(isa, 2000, "b1")
            + decoys
            + _work(isa, 500, "b2")
            + _exit(isa)
            + _epilogue())


def wl_missable(isa: str) -> list:
    """(C) the markers of (A), entered MID-sequence through a branch — which
    under whole-block matching is NOT a marker and must open no window.

    An unconditional jump lands on the sequence's LAST instruction, so the
    translation block starts mid-sequence and contains fewer than
    CST_MARKER_SEQ_LEN magic instructions.  The whole-block ``memcmp`` cannot
    form a match against bytes that are not in the block, and base QEMU's
    never-split rule only keeps a sequence together when the block reaches it
    from the front — it does not reach backwards for a block entered at the
    tail.  So detection fires at TRANSLATION on the WHOLE sequence only, and
    a mid-sequence entry executes too few magic instructions to be one: the
    required outcome is the NEGATIVE — no window, no segment, guest exits 0.
    """
    def entered_mid(seq: list, label: str) -> list:
        return (_jump(isa, label)
                + seq[:-1]
                + [f"{label}:"]
                + seq[-1:])

    return (_prologue()
            + entered_mid(B.emit_trace_marker(isa), "Lmid_start")
            + _work(isa, 2000, "c1")
            + entered_mid(B.emit_trace_marker_end(isa), "Lmid_end")
            + _work(isa, 500, "c2")
            + _exit(isa)
            + _epilogue())


def _negative_self_check(isa: str) -> str:
    """Assert the negative workload really is negative, at the source level.

    A decoy workload that accidentally spells a complete sequence would pass
    the "no window opened" test for the wrong reason — or fail it while the
    plugin was right.  Both marker sequences must be absent from the decoy
    listing as contiguous instruction runs, and the terminating instruction of
    each must be PRESENT, so the whole-block match has a real marker tail to
    reject against and the rejection it then makes is a real rejection rather
    than a trivial mismatch on the last instruction.
    """
    lines = _insns(wl_negative(isa))
    start = _insns(B.emit_trace_marker(isa))
    end = _insns(B.emit_trace_marker_end(isa))
    if _contains_run(lines, start):
        return "decoy workload contains a COMPLETE START sequence"
    if _contains_run(lines, end):
        return "decoy workload contains a COMPLETE END sequence"
    if start[-1] not in lines:
        return ("decoy workload never presents the START sequence's "
                "terminating instruction — nothing to reject")
    if end[-1] not in lines:
        return ("decoy workload never presents the END sequence's "
                "terminating instruction — nothing to reject")
    return ""


# ===========================================================================
# CHECK 1 — features.marker_detection
# ===========================================================================

_RE_FIRED = re.compile(r"marker fired at icount (\d+)")
_RE_CLOSING = re.compile(r"end marker — closing after (\d+) user insns")
_RE_FINISHED = re.compile(
    r"finished segment \[icount \d+ \.\. \d+\].*?"
    r"user_covered=(\d+)\s+user_budget=(\d+).*?(\S+)\s*$")


def _build_workload(isa: str, d: Path, tag: str, lines: list):
    """Emit @lines as ``<tag>_<isa>.S`` in @d and build it through the
    validator's own toolchain path (``__main__.cmd_build``: ISA_COMPILER +
    ISA_CFLAGS, the same one every generated workload uses).  Returns the
    binary path, or None if the build failed."""
    from . import __main__ as M
    d.mkdir(parents=True, exist_ok=True)
    src = d / f"{tag}_{isa}.S"
    src.write_text("\n".join(lines) + "\n")
    if M.cmd_build(SimpleNamespace(out_dir=d, prog=tag), isa) != 0:
        return None
    binp = d / f"{tag}_{isa}"
    return binp if binp.is_file() else None


def _run_marker(ctx, isa: str, binp: Path, out_base: Path):
    """Run @binp under qemu-<isa> with a marker window.  Returns
    (rc, stderr)."""
    qemu = ctx.build_dir / f"qemu-{isa}"
    opts = (f"outfile={out_base},wpdepth=8,"
            f"trace_window=marker:simulation={MARKER_SIM_BUDGET}"
            f"+policy=latch")
    cmd = _taskset_prefix() + [str(qemu), "-plugin",
                               f"{ctx.plugin},{opts}", str(binp)]
    p = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, text=True, timeout=300)
    return p.returncode, p.stderr or ""


def _judge_positive(name: str, rc: int, err: str, cst: Path) -> tuple:
    """A complete sequence must open a window and close it AT THE END MARKER,
    with the budget nowhere near spent.  Every string this judges by must be
    found: a missing subject is a failure, never a pass."""
    if rc != 0:
        return False, f"{name}: guest exited rc={rc} (workload did not run)"
    if not _RE_FIRED.search(err):
        return False, (f"{name}: no 'marker fired at icount' — a COMPLETE "
                       f"START sequence was MISSED")
    m_close = _RE_CLOSING.search(err)
    if not m_close:
        return False, (f"{name}: window opened but no 'end marker — closing "
                       f"after' — a COMPLETE END sequence was MISSED")
    m_fin = None
    for ln in err.splitlines():
        if "finished segment" in ln:
            m_fin = _RE_FINISHED.search(ln.rstrip())
    if not m_fin:
        return False, (f"{name}: no parsable 'finished segment ... "
                       f"user_covered=.. user_budget=.. <flag>' line to judge "
                       f"the close by")
    covered, budget, flag = int(m_fin.group(1)), int(m_fin.group(2)), \
        m_fin.group(3)
    if flag != "END":
        return False, (f"{name}: segment closed '{flag}', expected 'END' "
                       f"(covered={covered} budget={budget})")
    if not cst.is_file():
        return False, f"{name}: closed at the END marker but wrote no {cst.name}"
    if covered <= 0:
        return False, f"{name}: END close with user_covered={covered}"
    if covered * MARKER_BUDGET_HEADROOM >= budget:
        return False, (f"{name}: user_covered={covered} is not far below "
                       f"user_budget={budget} — the close is not "
                       f"distinguishable from a budget close")
    return True, (f"{name}: fired, closed END, covered={covered} of "
                  f"budget={budget}")


def _judge_negative(name: str, rc: int, err: str, cst: Path) -> tuple:
    """No decoy may open a window.  The guest must still have RUN — the exit
    syscall sits after every decoy, so rc=0 is what proves the decoys
    retired."""
    if rc != 0:
        return False, (f"{name}: guest exited rc={rc} — the decoys are not "
                       f"proven to have executed")
    if _RE_FIRED.search(err):
        return False, (f"{name}: a window OPENED on decoys — an INCOMPLETE "
                       f"sequence was CLAIMED: "
                       + _RE_FIRED.search(err).group(0))
    if cst.is_file():
        return False, (f"{name}: no 'marker fired' but a segment was written "
                       f"({cst.name}, {cst.stat().st_size} bytes)")
    return True, f"{name}: no window, no segment (decoys ran, guest rc=0)"


def chk_marker_detection(ctx):
    """features.marker_detection — both directions of the marker invariant."""
    from . import __main__ as M
    subs: list = []
    ok_all = True
    ran_any = False

    for isa in MARKER_ISAS:
        qemu = ctx.build_dir / f"qemu-{isa}"
        cc = M.ISA_COMPILER.get(isa)
        if not qemu.is_file():
            subs.append({"name": isa, "ok": True,
                         "detail": f"skip: {qemu} not built"})
            continue
        if not cc or not M._have(cc):
            subs.append({"name": isa, "ok": True,
                         "detail": f"skip: cross compiler {cc} not in PATH"})
            continue

        bad = _negative_self_check(isa)
        if bad:
            ok_all = False
            subs.append({"name": f"{isa}/decoy-shape", "ok": False,
                         "detail": bad})
            continue
        subs.append({"name": f"{isa}/decoy-shape", "ok": True,
                     "detail": "decoys spell no complete sequence, and do "
                               "present both terminating instructions"})

        d = ctx.dir(f"feat_marker_detection_{isa}")
        for tag, build, judge in (
                ("positive", wl_positive, _judge_positive),
                ("negative", wl_negative, _judge_negative),
                # A mid-sequence branch entry is NOT a marker under
                # whole-block matching: it must open no window (negative).
                ("missable", wl_missable, _judge_negative)):
            name = f"{isa}/{tag}"
            binp = _build_workload(isa, d, tag, build(isa))
            if binp is None:
                ok_all = False
                subs.append({"name": name, "ok": False,
                             "detail": "workload failed to assemble/link"})
                continue
            out_base = d / f"{tag}_{isa}_trace"
            cst = Path(f"{out_base}.cst")
            if cst.exists():
                cst.unlink()
            try:
                rc, err = _run_marker(ctx, isa, binp, out_base)
            except subprocess.TimeoutExpired:
                ok_all = False
                subs.append({"name": name, "ok": False,
                             "detail": "qemu timed out (300s)"})
                continue
            ran_any = True
            ok, detail = judge(name, rc, err, cst)
            ok_all = ok_all and ok
            if not ok:
                (d / f"{tag}_{isa}.stderr").write_text(err)
                detail += f"  [stderr: {d / f'{tag}_{isa}.stderr'}]"
            subs.append({"name": name, "ok": ok, "detail": detail})

    # ORDER MATTERS.  A failure outranks a skip: the decoy-shape guard rejects
    # a workload before it is ever run, so an ISA can fail without adding to
    # ran_any, and testing ran_any first would report a REAL failure as
    # "nothing was verified".
    if not ok_all:
        return _outcome(
            "fail",
            "the marker invariant does not hold: "
            + next(s["detail"] for s in subs if not s["ok"]), subs)
    if not ran_any:
        return _outcome("skip",
                        "no ISA had both a qemu-<isa> binary and a cross "
                        "toolchain; nothing was verified", subs)
    return _outcome(
        "pass",
        "a complete marker sequence is never missed (plain), and an "
        "incomplete one is never claimed — neither the all-decoys shape nor "
        "a mid-sequence branch entry (which executes fewer than "
        f"CST_MARKER_SEQ_LEN magic instructions) opens a window "
        f"({', '.join(MARKER_ISAS)})", subs)


# ===========================================================================
# CHECK 2 — features.system_window_modes
# ===========================================================================

SYS_REFUSAL = "is not a valid window in system mode"
SYS_ACCEPTED_MARK = "marker window policy=latch"


def _system_probe(ctx, opts: str, timeout: int) -> tuple:
    """Install the plugin into the smallest possible qemu-system-x86_64.

    The window-mode decision is made in ``qemu_plugin_install``, before any
    machine setup, so no kernel and no rootfs are needed: a refused window
    makes the process exit non-zero on the spot.  ``-S`` keeps the guest CPU
    stopped so an ACCEPTED window has nothing to execute and the probe
    measures the install, not a boot.  Returns (rc, stderr, timed_out);
    rc is None when the process had to be killed.
    """
    qemu = ctx.build_dir / "qemu-system-x86_64"
    cmd = _taskset_prefix() + [
        str(qemu), "-display", "none", "-m", "128M", "-S",
    ]
    if opts is not None:
        cmd += ["-plugin", f"{ctx.plugin},{opts}"]
    try:
        p = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, text=True,
                           timeout=timeout)
        return p.returncode, p.stderr or "", False
    except subprocess.TimeoutExpired as e:
        err = e.stderr or ""
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return None, err, True


def chk_system_window_modes(ctx):
    """features.system_window_modes — both directions of the system-mode
    window restriction."""
    qemu = ctx.build_dir / "qemu-system-x86_64"
    if not qemu.is_file():
        return _outcome("skip", f"{qemu} not built")

    d = ctx.dir("feat_system_window_modes")
    sp = d / "one.simpoints"
    sp.write_text("0 0\n")
    base = f"outfile={d / 'sysw'}"

    subs: list = []
    ok_all = True

    # A marker anchor and a simpoint schedule are two separate inputs, and
    # neither implies the other: trace_window=simpoint states only that
    # SimPoint offsets are in use.  It therefore belongs on the refused list
    # for the same reason icount and symbol do -- it names positions on a
    # clock without saying whose clock -- and the composition below is where
    # a system-mode SimPoint capture is expressed.
    refused = [
        ("icount", f"{base},trace_window=icount:start=0+stop=100000"),
        ("symbol", f"{base},trace_window=symbol:name=main"
                   f"+simulation=100000"),
        ("simpoint (bare, no marker anchor)",
         f"{base},trace_window=simpoint:file={sp}"
         f"+interval=100000+simulation=100000"),
        ("default (no trace_window)", base),
    ]
    for name, opts in refused:
        rc, err, timed_out = _system_probe(ctx, opts, timeout=120)
        saw = SYS_REFUSAL in err
        ok = (not timed_out) and rc not in (0, None) and saw
        ok_all = ok_all and ok
        if timed_out:
            detail = "did NOT exit — a refused window must fail at install"
        elif rc == 0:
            detail = f"exited 0; refusal message {'seen' if saw else 'absent'}"
        elif not saw:
            detail = (f"exited {rc} but never printed "
                      f"'{SYS_REFUSAL}' — refused for some other reason")
        else:
            detail = f"refused at install, exit {rc}"
        subs.append({"name": f"refused/{name}", "ok": ok, "detail": detail})

    # ACCEPTED: the marker window must get past install.  With -S there is no
    # guest to run and nothing to close the window, so the process is expected
    # to be still alive at the timeout — judge the install, as specified.
    #
    # Both accepted forms run: the bare marker anchor, and the COMPOSITION —
    # simpoint offsets written onto that anchor.  The composition is the only
    # way a system-mode capture can use SimPoints at all now that the bare
    # simpoint window is refused above, so if it did not install, the refusal
    # would have removed a capability rather than renamed it.
    accepted = [
        ("marker",
         f"{base}_marker,trace_window=marker:simulation=100000+policy=latch"),
        ("marker+simpoints",
         f"{base}_marksp,trace_window=marker:simulation=100000"
         f"+policy=latch+simpoints={sp}+interval=100000+warmup=1000"),
    ]
    for name, opts in accepted:
        rc, err, timed_out = _system_probe(ctx, opts, timeout=25)
        saw_refusal = SYS_REFUSAL in err
        saw_install = SYS_ACCEPTED_MARK in err
        ok = (not saw_refusal) and saw_install
        ok_all = ok_all and ok
        if saw_refusal:
            detail = f"the {name} window was REFUSED in system mode"
        elif not saw_install:
            detail = (f"no '{SYS_ACCEPTED_MARK}' line — the plugin never got "
                      f"past install (rc={rc}, timed_out={timed_out})")
        else:
            detail = ("installed, window armed"
                      + (" (still running at the timeout, as expected)"
                         if timed_out else f" (exited {rc})"))
        subs.append({"name": f"accepted/{name}", "ok": ok, "detail": detail})

    if not ok_all:
        (d / "last.stderr").write_text(err)

    # The probes never run a guest: the refused arms exit inside
    # qemu_plugin_install and the accepted arm is killed with its CPU still
    # stopped.  The trace sidecars they leave behind therefore describe
    # nothing — the accepted arm's <outfile>.stats.log is opened at install
    # and written at exit, so being killed leaves it EMPTY.  Removing them
    # keeps them out of run_full's "(must be 0)" census, which is right to
    # refuse to read a stats.log with no rows in it and would otherwise be
    # failed by this check's own leftovers.
    for junk in d.glob("sysw*"):
        if junk.suffix in (".log", ".cst") or junk.name.endswith(".stats.log"):
            junk.unlink(missing_ok=True)

    msg = ("system mode needs a MARKER ANCHOR: icount / symbol / bare "
           "simpoint / the default are refused at install (non-zero exit + "
           "message); the marker window and simpoints COMPOSED onto it "
           "install")
    return _outcome("pass" if ok_all else "fail", msg, subs)
