"""Read an ELF's PT_LOAD content as a sparse byte map -- 32- OR 64-bit.

The riscv64 wrong-path leg's ``elfimage`` handles ELF64 only, and mipsel is
ELF32, so a second reader is needed rather than a widened one: the two class
layouts share no field offset past ``e_ident`` and a single parameterised
walker would be harder to read than two explicit ones.

The wrong-path leg lays the guest's own image back down at the guest's own
addresses, so the excursion executes the same bytes the tracer decoded.  Read
from the FILE rather than from a memory dump: the ELF is the only artefact
that is identical between the traced run and the injected one.

Author: Maccoy Merrell.
"""
import struct


def load(path):
    """-> ({addr: byte}, [(lo, hi) executable ranges], entry, is64)."""
    with open(path, 'rb') as fh:
        data = fh.read()
    if data[:4] != b'\x7fELF':
        raise RuntimeError('%s is not an ELF' % path)
    if data[5] != 1:
        raise RuntimeError('%s is not little-endian; this reader handles the '
                           'two little-endian classes only' % path)
    is64 = data[4] == 2
    if is64:
        e_entry, e_phoff = struct.unpack_from('<QQ', data, 0x18)
        e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x36)
    else:
        e_entry, e_phoff = struct.unpack_from('<II', data, 0x18)
        e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x2a)
    mem, xr = {}, []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if is64:
            p_type, p_flags = struct.unpack_from('<II', data, o)
            p_offset, p_vaddr = struct.unpack_from('<QQ', data, o + 8)
            p_filesz, p_memsz = struct.unpack_from('<QQ', data, o + 0x20)
        else:
            p_type, = struct.unpack_from('<I', data, o)
            p_offset, p_vaddr = struct.unpack_from('<II', data, o + 4)
            p_filesz, p_memsz = struct.unpack_from('<II', data, o + 0x10)
            p_flags, = struct.unpack_from('<I', data, o + 0x18)
        if p_type != 1:
            continue
        blob = data[p_offset:p_offset + p_filesz]
        for k, b in enumerate(blob):
            mem[p_vaddr + k] = b
        for k in range(p_filesz, p_memsz):
            mem[p_vaddr + k] = 0
        if p_flags & 1:
            xr.append((p_vaddr, p_vaddr + p_memsz))
    if not mem:
        raise RuntimeError('no PT_LOAD content in %s' % path)
    return mem, xr, e_entry, is64
