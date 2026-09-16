"""
Which ``.dep_refine`` family a given ENCODING's mnemonic row carried.

The retirement at ``508b474fe2`` deleted four of the nine families from the
generated tables, so the family an instruction USED TO carry cannot be read
out of the tree at HEAD.  It is read out of the tables as they stood at the
retirement's parent, which is where the 5,981 rows the arc counted still live,
and the encoding is bound to a row by DECODING IT -- never by matching
mnemonic text, which on x86 carries an AT&T size suffix (``movq``) that no
enum name has.

R8.7 is the reason for that shape: "a claim needs an OBSERVED decode or an
OBSERVED run, never a table row".  A row here is only ever reached from an
encoding the run actually executed.

Author: Maccoy Merrell.
"""
import collections
import re
import subprocess

import capstone

#: the generated tables, and the Capstone architecture that keys each.
_TABLES = {
    'x86_64': ('champsim_tracer_mnemonics_x86.h', 'X86_INS_'),
    'aarch64': ('champsim_tracer_mnemonics_aarch64.h', 'AArch64_INS_'),
    'riscv64': ('champsim_tracer_mnemonics_riscv.h', 'RISCV_INS_'),
    'mipsel': ('champsim_tracer_mnemonics_mips.h', 'MIPS_INS_'),
}

_ROW = re.compile(r'^\s*\[([A-Za-z0-9_]+)\]\s*=\s*\{')
_REF = re.compile(r'\.dep_refine\s*=\s*(dep_[a-z0-9_]+)')

#: the retirement commit.  Its PARENT holds the pre-retirement tables.
RETIREMENT = '508b474fe2'


def table_families(qemu_dir, isa, rev=RETIREMENT + '^'):
    """enum name -> refiner family, from the generated table at ``rev``.

    ``rev=None`` reads the working tree, which is how the SURVIVING families
    are read; the default reads the retirement's parent, which is the only
    place the four retired families still exist.
    """
    fname, _prefix = _TABLES[isa]
    path = 'contrib/plugins/champsim_tracer/' + fname
    if rev is None:
        with open('%s/%s' % (qemu_dir, path)) as fh:
            text = fh.read()
    else:
        text = subprocess.run(['git', '-C', qemu_dir, 'show',
                               '%s:%s' % (rev, path)],
                              stdout=subprocess.PIPE,
                              check=True).stdout.decode('utf-8', 'replace')
    # The rows are sequential designated initialisers inside ONE array, so
    # the array's own brace keeps the nesting depth at 1 for every row and a
    # depth test cannot delimit them.  The row header itself is the delimiter:
    # a `.dep_refine` belongs to the most recent `[ENUM] = {` seen.  Comment
    # lines are skipped so that prose naming a refiner cannot enter the map.
    out, cur = {}, None
    for line in text.splitlines():
        st = line.lstrip()
        if st.startswith('*') or st.startswith('/*') or st.startswith('//'):
            continue
        m = _ROW.match(line)
        if m:
            cur = m.group(1)
        if cur:
            r = _REF.search(line)
            if r:
                out[cur] = r.group(1)
    return out


#: The Capstone architecture per ISA, and the instruction-id prefix the
#: PYTHON binding spells.  The generated table spells the AArch64 one
#: ``AArch64_INS_`` while the binding spells it ``AARCH64_INS_``, so every
#: lookup here is case-normalised -- a mismatch that silently attributed 214
#: aarch64 decodes to no family at all before it was caught.
_CS = {
    'x86_64': (capstone.CS_ARCH_X86, capstone.CS_MODE_64, 'X86_INS_'),
    'aarch64': (capstone.CS_ARCH_AARCH64, capstone.CS_MODE_LITTLE_ENDIAN,
                'AARCH64_INS_'),
}


class Attributor(object):
    """Encoding -> the refiner family its row carried, with the misses counted.

    Every failure mode is a COUNTER, not an exception and not a silent skip:
    an encoding Capstone declines, an instruction id with no enum name, and an
    enum name absent from the table are three different facts and each of them
    bounds what the per-family scores mean.
    """

    def __init__(self, qemu_dir, isa, rev=RETIREMENT + '^'):
        arch, mode, prefix = _CS[isa]
        self.md = capstone.Cs(arch, mode)
        self.md.detail = False
        if isa == 'x86_64':
            self.md.syntax = capstone.CS_OPT_SYNTAX_ATT
        self.prefix = prefix
        self.fam = table_families(qemu_dir, isa, rev)
        self.now = table_families(qemu_dir, isa, rev=None)
        self._famU = dict((k.upper(), v) for k, v in self.fam.items())
        self._nowU = dict((k.upper(), v) for k, v in self.now.items())
        self.id_name = {}
        for nm in dir(capstone.x86 if isa == 'x86_64' else capstone.aarch64):
            if nm.startswith(prefix):
                mod = capstone.x86 if isa == 'x86_64' else capstone.aarch64
                self.id_name[getattr(mod, nm)] = nm
        self.miss = collections.Counter()
        self._cache = {}

    def family(self, pc, bits):
        """(family_at_retirement, family_now, enum) or (None, None, None)."""
        key = bytes(bits)
        if key in self._cache:
            return self._cache[key]
        res = (None, None, None)
        try:
            ins = next(self.md.disasm(key, pc, 1))
        except StopIteration:
            self.miss['capstone-declined'] += 1
            ins = None
        if ins is not None:
            enum = self.id_name.get(ins.id)
            if enum is None:
                self.miss['id-has-no-enum'] += 1
            elif (enum.upper() not in self._famU
                    and enum.upper() not in self._nowU):
                self.miss['enum-not-in-table'] += 1
                res = (None, None, enum)
            else:
                res = (self._famU.get(enum.upper()),
                       self._nowU.get(enum.upper()), enum)
        self._cache[key] = res
        return res
