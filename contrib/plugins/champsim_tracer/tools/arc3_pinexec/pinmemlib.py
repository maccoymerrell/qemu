#!/usr/bin/env python3
"""Reader for the ChampSim Tracer PIN memop reference stream (x86_64).

Author: Maccoy Merrell <maccoy.merrell@tamu.edu>

The stream is produced by `champsim_memop_pintool.cpp`; the layout below is
that file's `struct memop_rec`, which is `#pragma pack`ed, so every offset is
the sum of the fields before it and nothing realigns.

    off  size  field
      0     8  ip
      8     1  is_branch
      9     1  branch_taken
     10     1  n_ld      TRUE load-memop count for this dynamic instruction
     11     1  n_st      TRUE store-memop count
     12     1  ld_rec    loads this record actually holds (<= NMEM)
     13     1  st_rec    stores this record actually holds
     14     1  len       real instruction length
     15     1  pad
     16    16  bytes     raw encoding, zero-padded
     32    32  ld_ea[4]
     64    32  st_ea[4]
     96    16  ld_sz[4]
    112    16  st_sz[4]
    128     4  ld_got[4] bytes PIN_SafeCopy delivered per load
    132     4  st_got[4]
    136   128  ld_data[4][32]
    264   128  st_data[4][32]
    392        total

n_ld/n_st are the TRUE counts and ld_rec/st_rec the recorded ones: an
instruction with more memops than the record holds is visible as
`n_ld > ld_rec`, never as agreement.
"""
import numpy as np

NMEM = 4
DBYTES = 32
REC = 392

MEM_DT = np.dtype({
    'names': ['ip', 'is_branch', 'taken', 'n_ld', 'n_st', 'ld_rec', 'st_rec',
              'len', 'bytes', 'ld_ea', 'st_ea', 'ld_sz', 'st_sz',
              'ld_got', 'st_got', 'ld_data', 'st_data'],
    'formats': ['<u8', 'u1', 'u1', 'u1', 'u1', 'u1', 'u1',
                'u1', ('u1', 16), ('<u8', NMEM), ('<u8', NMEM),
                ('<u4', NMEM), ('<u4', NMEM),
                ('u1', NMEM), ('u1', NMEM),
                ('u1', (NMEM, DBYTES)), ('u1', (NMEM, DBYTES))],
    'offsets': [0, 8, 9, 10, 11, 12, 13,
                14, 16, 32, 64, 96, 112, 128, 132, 136, 264],
    'itemsize': REC,
})
assert MEM_DT.itemsize == REC


def read_memop(path, nrec=None):
    """Read the memop reference stream into a numpy structured array.

    A file whose size is not a whole number of records is a REFUSAL, not a
    truncation: silently reading a stream written by a differently-sized
    record would produce garbage that looks like data."""
    with open(path, 'rb') as f:
        raw = f.read() if nrec is None else f.read(nrec * REC)
    if len(raw) < REC:
        raise ValueError('%s: shorter than one %d-byte record' % (path, REC))
    if len(raw) % REC and nrec is None:
        raise ValueError('%s: %d bytes is not a whole number of %d-byte '
                         'records' % (path, len(raw), REC))
    n = len(raw) // REC
    return np.frombuffer(raw[:n * REC], dtype=MEM_DT)


def rec_bytes(a):
    """Per-record raw instruction bytes as a list of `bytes`."""
    bs = a['bytes']
    ln = a['len']
    return [bs[i, :ln[i]].tobytes() for i in range(len(a))]


def memop_value(data_row, got):
    """The little-endian integer of the `got` bytes PIN captured.

    This is the same encoding cst_decode prints for `ld=`/`st=`: the accessed
    bytes read as one little-endian integer."""
    return int.from_bytes(data_row[:got].tobytes(), 'little')
