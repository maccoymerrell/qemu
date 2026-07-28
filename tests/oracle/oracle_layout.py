"""Dump the layout of CPUArchState, as DWARF describes it, to JSON.

Run inside gdb:

    gdb --batch <qemu-binary> -x tests/oracle/oracle_layout.py \
        -ex "python dump('/path/out.json')"

The oracle reports the bytes of CPUArchState that an instruction changed.  For
the registers a target registers as TCG globals it can put a name to them; for
everything else -- vector files, FP status words, the flag words targets keep
outside the globals table -- it can only report an offset.  This turns those
offsets back into field paths, from the same debug information that describes
the build being measured, so nothing has to be written down per target and
nothing can drift from the binary it claims to describe.

Arrays are recorded as a descriptor rather than expanded: CPUArchState holds
some very large ones and the index is arithmetic anyway.  Unions are kept whole
with every arm, because which arm applies is a property of the instruction, not
of the layout -- MIPS fpr_t being the case that matters.

Copyright (c) 2026 Maccoy Merrell
SPDX-License-Identifier: GPL-2.0-or-later
"""

import json

import gdb


MAX_DEPTH = 12


def describe(t, depth=0):
    t = t.strip_typedefs()
    node = {"size": int(t.sizeof), "type": str(t)}

    if depth >= MAX_DEPTH:
        node["kind"] = "scalar"
        return node

    if t.code == gdb.TYPE_CODE_ARRAY:
        et = t.target()
        esz = int(et.sizeof) or 1
        node["kind"] = "array"
        node["n"] = int(t.sizeof) // esz
        node["elem_size"] = esz
        node["elem"] = describe(et, depth + 1)
        return node

    if t.code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
        node["kind"] = "union" if t.code == gdb.TYPE_CODE_UNION else "struct"
        kids = []
        try:
            fields = t.fields()
        except Exception:
            fields = []
        for f in fields:
            if getattr(f, "is_base_class", False):
                continue
            if f.bitpos is None:
                continue
            # A bitfield has no byte of its own to attribute a change to; note
            # it and move on rather than pretending it has one.
            if getattr(f, "bitsize", 0):
                kids.append({"name": f.name or "<anon>",
                             "off": f.bitpos // 8, "kind": "bitfield",
                             "size": max(1, (f.bitsize + 7) // 8),
                             "bitpos": f.bitpos, "bitsize": f.bitsize,
                             "type": str(f.type)})
                continue
            kid = describe(f.type, depth + 1)
            kid["name"] = f.name or "<anon>"
            kid["off"] = f.bitpos // 8
            kids.append(kid)
        node["children"] = kids
        return node

    node["kind"] = "scalar"
    return node


def dump(path, typename="CPUArchState"):
    t = gdb.lookup_type(typename)
    tree = describe(t)
    tree["name"] = typename
    tree["off"] = 0
    with open(path, "w") as fh:
        json.dump(tree, fh)
    print("oracle_layout: %s size=%d -> %s" % (typename, t.sizeof, path))
