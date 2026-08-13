"""Prove the built plugin can actually be LOADED.

Two commits on this branch ship a ``libchampsim_tracer.so`` that links and
then cannot be loaded: ``c7cdf3eddf`` calls ``close_seal_at_terminator()``
whose definition does not arrive until ``c6ca18a0d8``, so both objects carry
an undefined internal symbol::

    Could not load plugin .../libchampsim_tracer.so:
        undefined symbol: _Z24close_seal_at_terminatorjPK10BBTemplatem

A shared object may carry unresolved symbols and still link; whether that is
fatal is decided at load.  QEMU opens plugins with ``g_module_open(path,
G_MODULE_BIND_LOCAL)`` (``plugins/loader.c``), and GModule without
``G_MODULE_BIND_LAZY`` is ``RTLD_NOW``: every symbol must resolve before
``qemu_plugin_install`` is even looked up.  So the two commits build green
and are unusable, and nothing in the tree noticed.  The cost is not
theoretical — no bisection can cross that window, which is why ``25ad3052ea``,
a TRACE-CONTENT change, has never been observed in isolation by anyone.

WHY THIS IS NOT A PLAIN ``dlopen``
==================================

The plugin's undefined ``qemu_plugin_*`` symbols are satisfied by the QEMU
*executable*, not by any shared library, so a standalone
``dlopen(so, RTLD_NOW)`` fails on a perfectly good plugin::

    undefined symbol: qemu_plugin_register_asid_write_cb

The load has to happen inside a QEMU process to mean anything.  Two
invocations do it in tens of milliseconds without a guest image, and both
were verified against a deliberately broken object built to the exact shape
above (``libbroken.so``: exports ``qemu_plugin_version`` and
``qemu_plugin_install``, calls an undefined
``close_seal_at_terminator(unsigned, const BBTemplate *, unsigned long)``):

===========================================  ==========  ==============
invocation                                   broken .so  good .so
===========================================  ==========  ==============
``qemu-<isa> -plugin X /nonexistent``        load error  install ran
``qemu-system-<isa> -M none -plugin X``      load error  install ran
``qemu-<isa> -plugin X -version``            **rc 0**    rc 0
===========================================  ==========  ==============

The third is why this module runs a real invocation and not the obvious cheap
one: ``-version`` exits before plugins are loaded, so it reports success on
an object that cannot be loaded at all — a check that cannot see its subject
and says nothing.  It was measured, not assumed.

THE VERDICT IS READ FROM THE OUTPUT, NOT THE EXIT STATUS.  Both probes exit
nonzero on a good plugin too (no guest binary / no machine), so the exit
status carries no signal.  What separates them is that on a good plugin
``qemu_plugin_install`` RUNS — it prints the tracer's own banner, or QEMU
reports its return code — whereas a load failure names the missing symbol and
``install`` is never reached.

EVERY PROBE PROVES IT CAN FAIL, ON EVERY RUN
============================================

Reading a verdict out of the ABSENCE of a string is how a check comes to pass
on a program that never looked.  The first draft of this module did exactly
that and was caught by it: scanning the build dir for a user-mode emulator
picked up ``qemu-bridge-helper``, which ignores ``-plugin`` entirely, printed
nothing, and was scored "loads".  A build whose plugin could not load would
have been passed by that probe.

So each candidate binary is first run against a plugin path that CANNOT load
(``/nonexistent...so``).  A binary that does not report a load failure for a
plugin that does not exist cannot report one for a plugin that does not
resolve, and is discarded as a probe rather than trusted.  If no candidate
survives, the check FAILS — it could not ask its question.

Author: Maccoy Merrell
SPDX-License-Identifier: GPL-2.0-or-later
"""

from __future__ import annotations

import glob
import os
import subprocess
import tempfile
from pathlib import Path

#: QEMU's own message when the load stage failed, whatever the reason
#: (missing symbol, missing file, missing API version).
_LOAD_FAILED = "Could not load plugin"

#: ... except this one, which is emitted only AFTER a successful load: the
#: plugin's install function was found, called, and returned nonzero.  It is
#: positive evidence that every symbol resolved.
_INSTALL_RAN = "qemu_plugin_install returned error code"

_PROBE_TIMEOUT_S = 60


def find_plugin(build_dir: Path) -> Path:
    return build_dir / "contrib" / "plugins" / "libchampsim_tracer.so"


#: A plugin path that cannot exist, used as each probe's own control arm.
_NO_SUCH_PLUGIN = "/nonexistent-plugin-that-cannot-load.so"


def _candidates(build_dir: Path) -> list[tuple[str, list[str]]]:
    """(name, argv-prefix) for every binary in @build_dir that might load a
    plugin; the plugin path is appended by the caller.  Deliberately
    permissive — :func:`_usable` is what decides, by measurement."""
    out: list[tuple[str, list[str]]] = []
    for q in sorted(glob.glob(str(build_dir / "qemu-system-*"))):
        if os.path.isfile(q) and os.access(q, os.X_OK):
            out.append((os.path.basename(q),
                        [q, "-M", "none", "-display", "none",
                         "-monitor", "none", "-serial", "none",
                         "-no-user-config", "-plugin"]))
    for q in sorted(glob.glob(str(build_dir / "qemu-*"))):
        b = os.path.basename(q)
        if b.startswith("qemu-system-") or "." in b:
            continue
        if os.path.isfile(q) and os.access(q, os.X_OK):
            out.append((b, [q, "-plugin"]))
    return out


def _run(argv: list[str], scratch_in: Path) -> str | None:
    """Run a probe in a scratch directory.  A probe that gets as far as
    ``qemu_plugin_install`` — which is the whole point — installs the tracer,
    and the tracer opens its ``champsim_tracer_out.*`` sidecars relative to
    the process's working directory.  Running in a throwaway cwd keeps the
    proof of a successful load from leaving three files in whatever tree the
    validator happened to be invoked from; @scratch_in places that directory
    beside the build dir rather than on the OS disk."""
    parent = str(scratch_in) if os.access(scratch_in, os.W_OK) else None
    try:
        with tempfile.TemporaryDirectory(prefix=".cst-plugload-",
                                         dir=parent) as d:
            p = subprocess.run(argv, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, cwd=d,
                               timeout=_PROBE_TIMEOUT_S)
            return p.stdout.decode("utf-8", "replace")
    except (subprocess.TimeoutExpired, OSError):
        return None


def _tail(argv: list[str], plugin: str) -> list[str]:
    """The user-mode form needs a guest path after the plugin argument; the
    system form does not."""
    return [plugin] if "-M" in argv else [plugin,
                                          "/nonexistent-guest-binary"]


def check(build_dir: Path, label: str = "",
          max_probes: int = 2) -> tuple[bool, list[str]]:
    """(ok, lines).  False when the plugin in @build_dir cannot be loaded, or
    when the question could not be asked — an unaskable question is a
    failure here, never a pass."""
    lines: list[str] = []
    tag = f"plugin_load[{label}]" if label else "plugin_load"
    # Absolute throughout: the probes run in a scratch cwd, so a relative
    # build-dir path would resolve against the wrong directory.
    build_dir = Path(build_dir).resolve()
    plugin = find_plugin(build_dir)
    if not plugin.is_file():
        lines.append(f"{tag}: FAIL  no plugin at {plugin}")
        return False, lines

    ok = True
    used = 0
    rejected: list[str] = []
    for name, pre in _candidates(build_dir):
        if used >= max_probes:
            break
        # CONTROL ARM.  A binary that does not report a load failure for a
        # plugin that does not exist cannot report one for a plugin that
        # does not resolve.
        ctrl = _run(pre + _tail(pre, _NO_SUCH_PLUGIN), build_dir)
        if ctrl is None or _LOAD_FAILED not in ctrl:
            rejected.append(name)
            continue
        used += 1

        out = _run(pre + _tail(pre, str(plugin)), build_dir)
        if out is None:
            lines.append(f"{tag}: FAIL  {name} did not return within "
                         f"{_PROBE_TIMEOUT_S}s while loading {plugin.name}")
            ok = False
            continue
        if _LOAD_FAILED in out and _INSTALL_RAN not in out:
            why = next((l.strip() for l in out.splitlines()
                        if _LOAD_FAILED in l), out.strip()[:400])
            lines.append(
                f"{tag}: FAIL  {plugin.name} CANNOT BE LOADED by {name}: "
                f"{why}")
            lines.append(
                f"{tag}:       QEMU opens plugins RTLD_NOW, so an undefined "
                f"symbol is fatal at load however cleanly the object linked. "
                f"This build is unusable and unbisectable.")
            ok = False
            continue
        lines.append(f"{tag}: {plugin.name} loads under {name} "
                     f"(qemu_plugin_install reached; probe verified against "
                     f"a plugin that cannot load)")

    if used == 0:
        lines.append(
            f"{tag}: FAIL  no binary in {build_dir} could be verified to "
            f"report a plugin load failure"
            + (f" (rejected: {', '.join(rejected[:8])})" if rejected else "")
            + " — whether the plugin loads could not be asked, and an "
              "unasked question is not a pass")
        return False, lines
    return ok, lines


# Memoised so every trace path can assert it without paying for it twice.
_seen: dict[tuple[str, int, int], tuple[bool, list[str]]] = {}


def check_once(build_dir: Path, label: str = "") -> tuple[bool, list[str]]:
    plugin = find_plugin(build_dir)
    try:
        st = plugin.stat()
        key = (str(plugin), st.st_mtime_ns, st.st_size)
    except OSError:
        key = (str(plugin), 0, 0)
    if key not in _seen:
        _seen[key] = check(build_dir, label=label)
    return _seen[key]


def cmd_plugin_load(args) -> int:
    ok, lines = check(args.build_dir, label=getattr(args, "label", "") or "")
    for line in lines:
        print(line)
    print("plugin_load: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def add_parser(sub) -> None:
    c = sub.add_parser(
        "plugin_load",
        help="Prove the built plugin can be loaded by QEMU (RTLD_NOW), not "
             "merely linked")
    c.add_argument("--build-dir", type=Path, required=True)
    c.add_argument("--label", default="")
