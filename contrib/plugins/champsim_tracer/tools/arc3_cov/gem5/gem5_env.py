"""
ARC 3 -- the named prerequisites of the gem5 execution leg.

``gem5.opt`` embeds the CPython that BUILT it: ``libpython3.11.so.1.0`` appears
in its ``DT_NEEDED`` and there is no ``RUNPATH`` to find it with.  On a host
whose system interpreter is a different version, that library exists only
inside the Anaconda installation gem5 was configured against, and the leg is
unrunnable until the loader is pointed at it.

So the interpreter is exposed through a SHIM DIRECTORY holding exactly one
symlink -- the ``libpython`` soname gem5 asked for -- and nothing else.  Every
other library keeps resolving the way it did at link time.

THE SECOND HALF OF THIS DOCSTRING USED TO CLAIM A SEGFAULT.  It said that
putting the whole Anaconda ``lib`` on ``LD_LIBRARY_PATH`` makes gem5 SIGSEGV,
because Anaconda ships ``libstdc++.so.6`` at ``GLIBCXX_3.4.29`` while gem5 was
compiled against ``GLIBCXX_3.4.33``, and it quoted a per-library table with
``libstdc++.so.6 -> exit 139``.  **RE-MEASURED 2026-08-28 against the gem5.opt
now on this host (X86, built 2026-08-24) and it does not reproduce, in either
half of the argument** (evidence
``cst_runs/p3/arc3/exec33/statics/gem5env/REMEASURE.txt``):

* the PREMISE is false for this binary -- the highest ``GLIBCXX`` symbol
  version gem5.opt actually requires is ``3.4.29``, which is exactly what
  Anaconda's ``libstdc++`` provides.  The system copy's ``3.4.33`` is a
  ceiling gem5 never reaches.
* the OUTCOME is false -- with Anaconda's ``libstdc++`` resolving in front
  (confirmed by ``ldd`` under the same environment), gem5 runs a config,
  executes its embedded Python and exits 0.  So does the whole-``lib`` arm the
  docstring called "the obvious way".  Every arm exits 0; the only non-zero
  reading in the sweep is the arm with NO shim, which exits 127 because
  ``libpython3.11.so.1.0`` is not found.

**WHAT IS LOAD-BEARING, then, is the libpython half alone**, and it is
load-bearing absolutely: without the shim there is no run at all.

**AND THE NEVER-DO SURVIVES, restated as what it is.**  ``sanitize_ld_path``
below still drops any inherited directory that supplies ``libstdc++.so.6`` or
``libgcc_s.so.1``, and that is kept deliberately -- but as a PROSPECTIVE guard
on a real hazard, not as the reproduction of a measured crash.  The hazard is
structural: those two are the C++ ABI gem5 was compiled against, an inherited
``LD_LIBRARY_PATH`` can substitute an older copy for either, and the failure
mode when the versions genuinely do not line up is a crash inside the embedded
interpreter rather than a loader diagnostic.  Today's gem5 happens to be
compatible with both copies on this host; a gem5 rebuilt by a newer compiler
would not be, and the guard costs nothing.  It is never to be removed on the
strength of "it does not segfault now" -- which is exactly what this
re-measurement says, and exactly why the sentence is here.

Everything here raises ``MissingPrerequisite``, whose message NAMES the thing
that is absent.  A leg that cannot run must say what it needs; it must never
hand a segfault to the caller and let a facet cell read CITED forever.

Author: Maccoy Merrell.
"""
import os
import struct
import sys


class MissingPrerequisite(Exception):
    """A named, actionable absence.  Never a stack trace, never a signal."""


# ------------------------------------------------------------------- the ELF
def _elf_dt_needed(path):
    """The DT_NEEDED sonames of an ELF64 little-endian file, in order.

    Parsed here rather than shelled out to ``objdump``/``readelf`` so that the
    prerequisite check does not itself have a prerequisite.
    """
    with open(path, 'rb') as fh:
        ident = fh.read(16)
        if ident[:4] != b'\x7fELF':
            raise MissingPrerequisite(
                'not an ELF file: %s -- expected the gem5 binary' % path)
        if ident[4] != 2 or ident[5] != 1:
            raise MissingPrerequisite(
                'gem5 binary %s is not ELF64 little-endian; this reader '
                'handles only the host format it was written for' % path)
        fh.seek(0)
        hdr = fh.read(64)
        e_phoff, = struct.unpack_from('<Q', hdr, 32)
        e_phentsize, e_phnum = struct.unpack_from('<HH', hdr, 54)

        dyn_off = dyn_size = None
        for i in range(e_phnum):
            fh.seek(e_phoff + i * e_phentsize)
            ph = fh.read(e_phentsize)
            p_type, = struct.unpack_from('<I', ph, 0)
            if p_type == 2:                       # PT_DYNAMIC
                dyn_off, = struct.unpack_from('<Q', ph, 8)
                dyn_size, = struct.unpack_from('<Q', ph, 32)
                break
        if dyn_off is None:
            raise MissingPrerequisite(
                'gem5 binary %s has no PT_DYNAMIC segment; it cannot be the '
                'dynamically linked gem5.opt this leg drives' % path)

        fh.seek(dyn_off)
        dyn = fh.read(dyn_size)
        needed_offs, strtab_va, strsz = [], None, None
        for off in range(0, len(dyn) - 15, 16):
            tag, val = struct.unpack_from('<qQ', dyn, off)
            if tag == 0:                          # DT_NULL
                break
            elif tag == 1:                        # DT_NEEDED
                needed_offs.append(val)
            elif tag == 5:                        # DT_STRTAB
                strtab_va = val
            elif tag == 10:                       # DT_STRSZ
                strsz = val
        if strtab_va is None:
            raise MissingPrerequisite(
                'gem5 binary %s has no DT_STRTAB; DT_NEEDED cannot be read'
                % path)

        # DT_STRTAB is a virtual address; map it back through the program
        # headers to a file offset.
        strtab_off = None
        for i in range(e_phnum):
            fh.seek(e_phoff + i * e_phentsize)
            ph = fh.read(e_phentsize)
            p_type, = struct.unpack_from('<I', ph, 0)
            if p_type != 1:                       # PT_LOAD
                continue
            p_offset, p_vaddr = struct.unpack_from('<QQ', ph, 8)
            p_filesz, = struct.unpack_from('<Q', ph, 32)
            if p_vaddr <= strtab_va < p_vaddr + p_filesz:
                strtab_off = p_offset + (strtab_va - p_vaddr)
                break
        if strtab_off is None:
            raise MissingPrerequisite(
                'DT_STRTAB 0x%x in %s falls in no PT_LOAD segment'
                % (strtab_va, path))

        fh.seek(strtab_off)
        blob = fh.read(strsz or 1 << 20)

    out = []
    for o in needed_offs:
        end = blob.find(b'\0', o)
        out.append(blob[o:end].decode('utf-8', 'replace'))
    return out


def libpython_soname(gem5_bin):
    """The ``libpython*.so*`` gem5 was linked against, or None if static."""
    for soname in _elf_dt_needed(gem5_bin):
        if soname.startswith('libpython'):
            return soname
    return None


# ----------------------------------------------------------- finding the lib
def _default_search(soname):
    """Where to look for the interpreter, most-specific first.

    ``sys.executable``'s own installation comes first because the documented
    way to run this leg is under the same Anaconda interpreter that configured
    gem5 (``python3-config`` on PATH at build time).
    """
    dirs = []
    exe_prefix = os.path.dirname(os.path.dirname(os.path.abspath(
        sys.executable)))
    dirs.append(os.path.join(exe_prefix, 'lib'))
    try:
        import sysconfig
        for k in ('LIBDIR', 'LIBPL'):
            v = sysconfig.get_config_var(k)
            if v:
                dirs.append(v)
    except Exception:
        pass
    dirs += ['/usr/lib/x86_64-linux-gnu', '/usr/lib', '/usr/local/lib']
    seen, out = set(), []
    for d in dirs:
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def locate_libpython(soname, python_home=None, explicit_dir=None):
    """Absolute path of ``soname``, or ``MissingPrerequisite`` naming it."""
    cands = []
    if explicit_dir:
        cands.append(explicit_dir)
    if python_home:
        cands.append(os.path.join(python_home, 'lib'))
    cands += _default_search(soname)
    for d in cands:
        p = os.path.join(d, soname)
        if os.path.exists(p):
            return os.path.realpath(p)
    raise MissingPrerequisite(
        'MISSING PREREQUISITE: %s\n'
        '  gem5.opt names it in DT_NEEDED and carries no RUNPATH, so the '
        'loader cannot find it\n'
        '  on its own.  It is the interpreter gem5 was BUILT against '
        '(scons reported\n'
        '  "Using Python config: python3-config"; that config must resolve '
        'to the same one).\n'
        '  Searched, in order:\n%s\n'
        '  Fix: run this leg under that interpreter, or pass '
        '--python-home <prefix>\n'
        '  (the prefix whose lib/ holds %s), or set CST_GEM5_PYLIB to the '
        'directory holding it.'
        % (soname, '\n'.join('    %s' % d for d in cands), soname))


# ------------------------------------------------------------------ the shim
def make_pylib_shim(libpython_path, cache_dir):
    """A directory holding ONLY ``libpython``, for ``LD_LIBRARY_PATH``.

    Deliberately not the interpreter's own ``lib``.  Exposing that directory
    substitutes the interpreter's ``libstdc++``/``libgcc_s`` for the ones gem5
    was linked against, and this module will not do that by accident -- see
    the module docstring for what that was measured to cost (2026-08-28: on
    THIS gem5, nothing; the guard is prospective and stays).
    """
    d = os.path.join(cache_dir, 'pylib')
    os.makedirs(d, exist_ok=True)
    link = os.path.join(d, os.path.basename(libpython_path))
    if os.path.islink(link) or os.path.exists(link):
        try:
            if os.path.realpath(link) == libpython_path:
                return d
        except OSError:
            pass
        os.remove(link)
    os.symlink(libpython_path, link)
    return d


# --------------------------------------------- an LD_LIBRARY_PATH that is safe
#: Libraries whose ABI gem5 is compiled against.  A directory on the inherited
#: ``LD_LIBRARY_PATH`` that supplies one of these can override the copy gem5
#: was linked with.  PROSPECTIVE, not historical: re-measured 2026-08-28, this
#: gem5 runs fine either way (module docstring).  The substitution is still
#: never made deliberately, because when the versions DO diverge the failure
#: lands inside the embedded interpreter with no loader diagnostic.
ABI_LIBS = ('libstdc++.so.6', 'libgcc_s.so.1')


def sanitize_ld_path(inherited):
    """(kept dirs, [(dropped dir, the ABI library it supplied)])."""
    keep, dropped = [], []
    for d in (inherited or '').split(os.pathsep):
        if not d:
            continue
        hit = [lib for lib in ABI_LIBS if os.path.exists(os.path.join(d, lib))]
        if hit:
            dropped.append((d, hit[0]))
        else:
            keep.append(d)
    return keep, dropped


def gem5_environment(gem5_bin, cache_dir, python_home=None,
                     explicit_dir=None, base_env=None):
    """``(env, notes)`` -- an environment in which gem5 can actually start.

    ``notes`` records every decision so the run log says WHY the loader path
    looks the way it does.  Nothing here is silent.
    """
    env = dict(base_env if base_env is not None else os.environ)
    notes = []

    soname = libpython_soname(gem5_bin)
    if soname is None:
        notes.append('gem5.opt links no libpython (statically embedded '
                     'interpreter); no shim needed')
        return env, notes

    path = locate_libpython(soname, python_home=python_home,
                            explicit_dir=explicit_dir or
                            os.environ.get('CST_GEM5_PYLIB'))
    notes.append('interpreter gem5 was built against: %s -> %s'
                 % (soname, path))

    shim = make_pylib_shim(path, cache_dir)
    keep, dropped = sanitize_ld_path(env.get('LD_LIBRARY_PATH', ''))
    for d, lib in dropped:
        notes.append('DROPPED from LD_LIBRARY_PATH: %s -- it supplies %s, '
                     'which would override the copy gem5 was compiled '
                     'against (prospective ABI guard, see gem5_env.py)'
                     % (d, lib))
    env['LD_LIBRARY_PATH'] = os.pathsep.join([shim] + keep)
    notes.append('LD_LIBRARY_PATH=%s' % env['LD_LIBRARY_PATH'])
    return env, notes


# ------------------------------------------------------------- the other ones
def require_file(path, what):
    if not os.path.exists(path):
        raise MissingPrerequisite(
            'MISSING PREREQUISITE: %s\n  expected at: %s' % (what, path))
    return path
