"""BEHAVIOUR-BEARING IDENTITY OF A BUILT BINARY.

WHY THIS EXISTS (#292).  The R13 external-truth gate refuses a report that is
older than the binaries it claims to have measured.  That guard was keyed on
FILE IDENTITY -- the mtime of the plugin, the offline decoder and every
emulator in the build directory.  QEMU regenerates `qemu-version.h` from
`git describe`, so EVERY commit changes the version string, relinks all 62
emulators, and moves all 62 mtimes.  A comment-only commit therefore staled
every execution leg, and the gate could not end green without re-running
gem5, Spike and PIN -- hours of work to answer a question about a comment.

The guard is now keyed on the BYTES THAT CAN CHANGE BEHAVIOUR instead.  For
each binary we hash the contents of its allocatable SHT_PROGBITS sections
(.text, .rodata, .data, .data.rel.ro, .got, ...) and the sizes of its
allocatable SHT_NOBITS sections (.bss), with the version stamp masked out.
Everything a rebuild changes without changing behaviour is excluded by
construction:

  * DWARF and .comment are not allocatable, so a line-number shift from an
    inserted comment never reaches the digest;
  * `.note.gnu.build-id` is SHT_NOTE, not PROGBITS, and it is a hash of the
    whole output -- including the version string -- so including it would
    defeat the entire exercise;
  * the version string itself is masked wherever it appears.

WHAT IT DELIBERATELY DOES NOT ABSORB, and this is a REFUSAL, not an oversight:
a version string whose LENGTH changes.  `-dirty` appearing or disappearing
moves the string by six bytes, which moves every rodata object the linker
placed after it, which moves the addresses .text refers to.  Those are real
byte differences in behaviour-bearing sections and no mask can honestly
remove them.  In that case the digest moves, the reference advances, and the
gate reports stale -- the CONSERVATIVE direction.  A false red costs a re-run;
a false green is a lie about what was measured.

WHAT THE REFERENCE ACTUALLY IS.  Not the digest: a TIME.  For each binary the
build directory carries a small cache recording the digest last seen and the
mtime at which that digest FIRST appeared.  A relink that leaves the digest
unchanged updates the recorded mtime but NOT that first-seen time, so the
staleness reference does not advance.  A relink that changes the digest sets
the first-seen time to the new mtime, and every report older than it is
stale.  The reference is the newest first-seen time over all the binaries.

The cache is an optimisation and a memory, never an authority: if it is
missing, unreadable or unwritable, every binary's first-seen time falls back
to its current mtime and the guard degrades exactly to the old behaviour.

Author: Maccoy Merrell.
"""

import hashlib
import json
import os
import re
import struct
import sys

# ELF constants, spelled out rather than imported: this file must work with a
# bare interpreter, because a gate that needs a package installed is a gate
# that silently does not run.
_ELFMAG = b'\x7fELF'
_ELFCLASS64 = 2
_ELFDATA2LSB = 1
_SHT_PROGBITS = 1
_SHT_NOBITS = 8
_SHF_ALLOC = 0x2

CACHE_NAME = '.cst_behavior_ref.json'
CACHE_VERSION = 2


class NotAnElf(Exception):
    pass


def _sections(fh):
    """Yield (name, sh_type, sh_flags, sh_offset, sh_size) for an ELF64 LE."""
    fh.seek(0)
    ident = fh.read(16)
    if len(ident) < 16 or ident[:4] != _ELFMAG:
        raise NotAnElf('not an ELF file')
    if ident[4] != _ELFCLASS64 or ident[5] != _ELFDATA2LSB:
        raise NotAnElf('not a 64-bit little-endian ELF')
    fh.seek(0x28)
    hdr = fh.read(0x18)
    if len(hdr) < 0x18:
        raise NotAnElf('truncated ELF header')
    # e_shoff at 0x28; e_shentsize at 0x3A, e_shnum at 0x3C, e_shstrndx 0x3E.
    (e_shoff,) = struct.unpack_from('<Q', hdr, 0)
    fh.seek(0x3A)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHH', fh.read(6))
    if e_shentsize < 64 or e_shnum == 0:
        raise NotAnElf('no section headers')
    fh.seek(e_shoff)
    raw = fh.read(e_shentsize * e_shnum)
    if len(raw) < e_shentsize * e_shnum:
        raise NotAnElf('truncated section headers')

    def shdr(i):
        off = i * e_shentsize
        (sh_name, sh_type, sh_flags, _sh_addr, sh_offset,
         sh_size) = struct.unpack_from('<IIQQQQ', raw, off)
        return sh_name, sh_type, sh_flags, sh_offset, sh_size

    _n, _t, _f, str_off, str_size = shdr(e_shstrndx)
    fh.seek(str_off)
    strtab = fh.read(str_size)

    for i in range(e_shnum):
        sh_name, sh_type, sh_flags, sh_offset, sh_size = shdr(i)
        end = strtab.find(b'\0', sh_name)
        name = strtab[sh_name:end if end >= 0 else None].decode(
            'utf-8', 'replace')
        yield name, sh_type, sh_flags, sh_offset, sh_size


def version_stamps(build_dir):
    """The literal strings a rebuild changes without changing behaviour.

    Read from the build's own `qemu-version.h` rather than from a pattern,
    because the pattern would have to be kept in step with
    scripts/qemu-version.sh by hand and would go stale silently.  Longest
    first, so masking the full version does not leave the package version
    behind as a shorter substring.
    """
    path = os.path.join(build_dir, 'qemu-version.h')
    out = []
    try:
        text = open(path, errors='replace').read()
    except OSError:
        return out
    for m in re.finditer(r'^#define\s+QEMU_\w*VERSION\s+"([^"]*)"',
                         text, re.M):
        val = m.group(1)
        if val:
            out.append(val.encode())
    out.sort(key=len, reverse=True)
    return out


def digest(path, stamps=()):
    """sha256 over the behaviour-bearing bytes of an ELF file.

    Raises NotAnElf for anything this cannot read.  A caller that swallows
    that and substitutes a constant would be building a check with no
    subject; callers here fall back to raw mtime instead and say so.
    """
    h = hashlib.sha256()
    h.update(b'cst-behaviour-digest-v%d\n' % CACHE_VERSION)
    with open(path, 'rb') as fh:
        for name, sh_type, sh_flags, sh_offset, sh_size in _sections(fh):
            if not (sh_flags & _SHF_ALLOC):
                continue
            if sh_type == _SHT_NOBITS:
                # No file content; its SIZE is still behaviour (a .bss that
                # grew is a program that changed).
                h.update(b'N\0%s\0%d\n' % (name.encode(), sh_size))
                continue
            if sh_type != _SHT_PROGBITS:
                # .note.gnu.build-id lives here, and it is a hash of the whole
                # link including the version stamp -- including it would make
                # the mask pointless.  Dynamic-linking tables are derived, not
                # authored.
                continue
            fh.seek(sh_offset)
            data = fh.read(sh_size)
            if len(data) != sh_size:
                raise NotAnElf('section %s truncated' % name)
            data = mask_stamps(data, stamps)
            h.update(b'P\0%s\0%d\n' % (name.encode(), sh_size))
            h.update(data)
    return h.hexdigest()


# THE STAMP DOES NOT ALWAYS SURVIVE THE LINK IN ONE PIECE.
#
# Masking whole occurrences is not enough, and the softmmu binaries are where
# that shows.  Measured on qemu-system-aarch64 across a real commit (only the
# version string changed), .rodata carried the stamp TWICE: once verbatim
# inside "QEMU emulator version ...", and once at 0x196e30 as
#
#     v10.0.8-1270-g23  270-g23da1c79b7\0
#
# -- the linker's merged string pool holding a 16-byte head and the matching
# 15-byte tail adjacent, with no verbatim copy of the whole stamp anywhere
# near.  Masking literals left both fragments, so 29 of 62 emulators reported
# a behaviour change for a version bump and the fix delivered nothing where it
# was needed most.
#
# So fragments are masked too: at every place the stamp's first eight bytes
# occur, the longest matching PREFIX is zeroed, and at every place its last
# eight bytes occur, the longest matching SUFFIX is zeroed -- both only when
# the fragment reaches MIN_FRAGMENT bytes, which is what keeps this from
# turning into a licence to zero any byte that looks version-ish.  Two
# memchr-speed scans per stamp, not one scan per candidate length.
MIN_FRAGMENT = 12
_ANCHOR = 8


def mask_stamps(data, stamps):
    """Zero every whole occurrence of each stamp, and every long fragment."""
    out = None
    for s in stamps:
        if len(s) < MIN_FRAGMENT:
            continue
        head, tail = s[:_ANCHOR], s[-_ANCHOR:]
        hits = []
        # Whole occurrences and head-anchored prefixes are the same walk: at a
        # head hit, extend as far as the stamp still agrees.
        i = data.find(head)
        while i >= 0:
            n = _ANCHOR
            while (n < len(s) and i + n < len(data)
                   and data[i + n] == s[n]):
                n += 1
            if n >= MIN_FRAGMENT:
                hits.append((i, n))
            i = data.find(head, i + 1)
        # Tail-anchored suffixes: walk backwards from the end of the hit.
        j = data.find(tail)
        while j >= 0:
            end = j + _ANCHOR
            n = _ANCHOR
            while (n < len(s) and end - n - 1 >= 0
                   and data[end - n - 1] == s[len(s) - n - 1]):
                n += 1
            if n >= MIN_FRAGMENT:
                hits.append((end - n, n))
            j = data.find(tail, j + 1)
        if hits:
            if out is None:
                out = bytearray(data)
                data = out
            for off, n in hits:
                out[off:off + n] = b'\0' * n
    return bytes(data) if out is not None else data


def _load_cache(build_dir):
    path = os.path.join(build_dir, CACHE_NAME)
    try:
        with open(path) as fh:
            blob = json.load(fh)
    except (OSError, ValueError):
        return {}
    if blob.get('version') != CACHE_VERSION:
        return {}
    ent = blob.get('entries')
    return ent if isinstance(ent, dict) else {}


def _store_cache(build_dir, entries):
    path = os.path.join(build_dir, CACHE_NAME)
    tmp = path + '.tmp%d' % os.getpid()
    try:
        with open(tmp, 'w') as fh:
            json.dump({'version': CACHE_VERSION, 'entries': entries}, fh,
                      indent=1, sort_keys=True)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def behaviour_reference(build_dir, paths):
    """-> (since, which, rows)

    `since` is the newest first-seen-behaviour time over `paths`; `which` is
    the file that set it; `rows` is one (path, mtime, since, digest, note)
    per readable path so the caller can print what it held the reports
    against.  Paths that do not exist are skipped -- their absence is the
    caller's problem to report, not this function's to hide.
    """
    stamps = version_stamps(build_dir)
    cache = _load_cache(build_dir)
    out = {}
    rows = []
    best, which = 0.0, None
    for p in paths:
        if not os.path.exists(p):
            continue
        st = os.stat(p)
        prev = cache.get(p) or {}
        note = ''
        if (prev.get('mtime') == st.st_mtime
                and prev.get('size') == st.st_size
                and prev.get('digest')):
            d = prev['digest']
            since = prev.get('since', st.st_mtime)
            note = 'cached'
        else:
            try:
                d = digest(p, stamps)
            except (NotAnElf, OSError) as exc:
                # A file we cannot read the behaviour of is held at its raw
                # mtime.  Conservative, and named, so it cannot pass silently.
                rows.append((p, st.st_mtime, st.st_mtime, None,
                             'UNREADABLE (%s) -- held at raw mtime' % exc))
                if st.st_mtime > best:
                    best, which = st.st_mtime, p
                continue
            if prev.get('digest') == d:
                since = prev.get('since', st.st_mtime)
                note = 'relinked, behaviour unchanged'
            else:
                since = st.st_mtime
                note = ('behaviour CHANGED' if prev.get('digest')
                        else 'first seen')
        out[p] = {'mtime': st.st_mtime, 'size': st.st_size,
                  'digest': d, 'since': since}
        rows.append((p, st.st_mtime, since, d, note))
        if since > best:
            best, which = since, p
    if out:
        # Keep entries for paths not walked this time: a gate run restricted
        # to one ISA must not forget what the last full run learned.
        merged = dict(cache)
        merged.update(out)
        _store_cache(build_dir, merged)
    return best, which, rows


def _selfcheck():
    """Prove mask_stamps() on the byte patterns that were actually measured.

    The whole-literal case is easy and was never the problem.  The case that
    cost 29 emulators is the SPLIT one, and the bytes below are copied from
    qemu-system-aarch64 .rodata at 0x196e30 across a real commit: a 16-byte
    head and the matching 15-byte tail, adjacent, with no verbatim copy of the
    stamp anywhere in the region.  Two builds must reduce to the same bytes.
    """
    bad = 0

    def arm(name, a_bytes, a_stamps, b_bytes, b_stamps, want_equal):
        nonlocal bad
        a = mask_stamps(a_bytes, sorted(a_stamps, key=len, reverse=True))
        b = mask_stamps(b_bytes, sorted(b_stamps, key=len, reverse=True))
        got = (a == b)
        ok = (got == want_equal)
        print('%-28s %s (masked equal: %s, wanted: %s)'
              % (name, 'ok' if ok else 'FAILED', got, want_equal))
        if not ok:
            bad += 1

    s1 = b'v10.0.8-1269-gcd28220db7'
    s2 = b'v10.0.8-1270-g23da1c79b7'
    f1 = b'10.0.8 (v10.0.8-1269-gcd28220db7)'
    f2 = b'10.0.8 (v10.0.8-1270-g23da1c79b7)'

    arm('whole literal',
        b'QEMU emulator version ' + f1 + b'\nCopyright', [s1, f1],
        b'QEMU emulator version ' + f2 + b'\nCopyright', [s2, f2], True)

    arm('split head+tail (0x196e30)',
        b'\x0a\x00\x00' + s1[:16] + s1[9:] + b'\x00\x80\x00', [s1, f1],
        b'\x0a\x00\x00' + s2[:16] + s2[9:] + b'\x00\x80\x00', [s2, f2], True)

    # And the direction that must NOT collapse: real bytes either side of the
    # stamp have to survive, or the mask would be hiding the very changes the
    # guard exists to catch.
    arm('code either side survives',
        b'\x48\x89\xe5' + s1 + b'\xc3', [s1, f1],
        b'\x48\x89\xe5' + s2 + b'\x90', [s2, f2], False)
    arm('short lookalike not masked',
        b'v10.0.8-x', [s1, f1],
        b'v10.0.8-y', [s2, f2], False)
    return 1 if bad else 0


def _main(argv):
    """Print the behaviour digest of each named file.

    Exists so the gate's selftest can compare two fixtures WITHOUT a QEMU
    rebuild: the discrimination this file claims -- same behaviour under a
    changed stamp, different behaviour under changed code -- is a property of
    the digest, and can be proven on two thirty-byte shared objects.

      behavior_digest.py [--stamp S]... FILE...
    """
    if argv and argv[0] == '--selfcheck':
        return _selfcheck()
    stamps, files = [], []
    i = 0
    while i < len(argv):
        if argv[i] == '--stamp':
            i += 1
            if i >= len(argv):
                sys.stderr.write('--stamp needs a value\n')
                return 2
            stamps.append(argv[i].encode())
        else:
            files.append(argv[i])
        i += 1
    if not files:
        sys.stderr.write('no files named: a digest of nothing is not a '
                         'digest\n')
        return 2
    stamps.sort(key=len, reverse=True)
    rc = 0
    for f in files:
        try:
            print('%s  %s' % (digest(f, stamps), f))
        except (NotAnElf, OSError) as exc:
            print('UNREADABLE (%s)  %s' % (exc, f))
            rc = 1
    return rc


if __name__ == '__main__':
    import sys as _sys
    _sys.exit(_main(_sys.argv[1:]))
