"""Read a little-endian ELF64's PT_LOAD content as a sparse byte map.

The wrong-path leg lays the guest's own image back down at the guest's own
addresses, so the excursion executes the same bytes the tracer decoded.  Read
from the file rather than from a memory dump: the ELF is the only artefact
that is identical between the traced run and the injected one.

Author: Maccoy Merrell.
"""
import struct


def load(path):
    """-> ({addr: byte}, [(lo, hi) executable ranges], entry)."""
    with open(path, 'rb') as fh:
        data = fh.read()
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise RuntimeError('%s is not a little-endian ELF64' % path)
    e_entry, e_phoff = struct.unpack_from('<QQ', data, 0x18)
    e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x36)
    mem, xr = {}, []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from('<II', data, o)
        p_offset, p_vaddr = struct.unpack_from('<QQ', data, o + 8)
        p_filesz, p_memsz = struct.unpack_from('<QQ', data, o + 0x20)
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
    return mem, xr, e_entry
