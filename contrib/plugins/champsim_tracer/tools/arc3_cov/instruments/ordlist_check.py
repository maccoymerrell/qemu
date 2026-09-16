#!/usr/bin/env python3
"""Score QEMU's ORDERED register lists against its own membership bitmaps.

The producer (accel/tcg/insn-dataflow.c) records two things about the same
facts: a bitmap saying whether a register was read or written, and a list
saying in what order the translation stated it.  They are written by different
code at different sites, so they can disagree, and a list that has silently
lost a member is the failure mode the whole dataflow API is shaped around --
a short list is a missing dependency wearing the shape of a whole answer.

This reads a QEMU_DF_DUMP and checks, per instruction:

  MISSING   a member the bitmap has and the list does not.  The error that
            matters.  A list flip built on a short list publishes a register
            set the machine does not have.
  EXTRA     a member the list has and the bitmap does not, EXCLUDING the
            three kinds the bitmap cannot express (the architectural zero
            register, a discarded destination, and a source stated by NAME).
            Those are the reason the list exists; anything else here --
            including a kind this checker does not recognise -- is a
            fabricated member.
  NAME      entries of the third of those kinds, INSN_DF_ORD_NAME: a register
            the emulator resolved at translation time out of the CPU object
            rather than CPUArchState (aarch64 ARM_CP_CONST, e.g. MIDR_EL1),
            so it sets no bit in @rd and has no env range.  Reported on its
            own row and never merged into `ord`, because a kind the bitmap
            cannot check is a kind this checker is NOT checking and that has
            to be visible rather than assumed clean.
  DUP       one member twice in one list.  The append is idempotent by
            construction, so a hit means the idempotence key is wrong.
  TRUNC     a list that overflowed.  Not an error in itself -- it is the
            producer refusing -- but it is counted, because a consumer that
            never sees one has not tested the refusal path.

VACUITY: an empty dump, or one with no O lines at all, FAILS.  A checker that
cannot find its subject must not report success (#313).
"""
import sys
import collections

_FIXTURE = """\
D 0x1000 r reg=rax off=0 size=8 via=arg op=df argno=0
D 0x1000 w reg=rbx off=8 size=8 via=arg op=df argno=0 from=rax
D 0x1000 w reg=? off=928 size=16 via=st op=df argno=0 from=-
O 0x1000 r pos=0 global reg=rax
O 0x1000 w pos=0 global reg=rbx
O 0x1000 w pos=1 field off=928 size=16
O 0x1000 r pos=1 zeroreg
O 0x1000 r pos=2 name reg=MIDR_EL1
A 0x1000 ops=0 calls=0 opaque=0
"""


def selftest(tmpdir):
    """Prove every verdict this checker can reach is reachable.

    A checker whose failure arms have never fired is not evidence; a green
    from one is the absence of a test, not the absence of a defect.  Seven
    arms: the clean fixture passes, each of the four failure kinds is
    planted and must be caught, the NAME kind is proven COUNTED rather than
    merely tolerated, and a kind this checker does not know is proven to
    still score EXTRA.

    The zeroreg AND name lines are in the fixture on purpose -- both are
    members the D-line bitmap cannot express, so a checker that scored
    either as EXTRA would fail the clean arm.  The `bogus` arm is what keeps
    that tolerance narrow: it must be a WHITELIST of kinds, not a general
    amnesty for anything the parser did not recognise, and the arm fails the
    moment somebody widens it into one.
    """
    import os
    arms = [
        ("clean", _FIXTURE, 0, None),
        ("missing", _FIXTURE.replace("O 0x1000 r pos=0 global reg=rax\n", ""),
         1, "MISSING"),
        ("extra", _FIXTURE.replace("A 0x1000",
                                   "O 0x1000 r pos=2 global reg=rdx\nA 0x1000"),
         1, "EXTRA"),
        ("dup", _FIXTURE.replace("A 0x1000",
                                 "O 0x1000 r pos=2 global reg=rax\nA 0x1000"),
         1, "DUP"),
        ("vacuous", "", 1, "VACUOUS"),
        # The NAME kind is legitimate AND counted: a silent tolerance would
        # satisfy the clean arm while reporting nothing, which is the same
        # blindness in a quieter form.
        ("name", _FIXTURE, 0, "NAME=1"),
        # ... and an UNKNOWN kind is still a fabricated member.  This is the
        # arm that proves the name arm did not turn the EXTRA test off.
        ("bogus", _FIXTURE.replace("A 0x1000",
                                   "O 0x1000 r pos=3 wibble reg=zz\nA 0x1000"),
         1, "EXTRA"),
    ]
    ok = True
    for name, body, want_rc, want_word in arms:
        f = os.path.join(tmpdir, "arm_%s.df" % name)
        with open(f, "w") as fh:
            fh.write(body)
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            got = main(["ordlist_check.py", f])
        out = buf.getvalue()
        good = (got == want_rc) and (want_word is None or want_word in out)
        ok &= good
        print("selftest %-8s rc=%d want=%d word=%-8s -> %s"
              % (name, got, want_rc, want_word or "-",
                 "OK" if good else "BROKEN"))
        if not good:
            print(out.rstrip())
    print("selftest: %s" % ("ALL %d ARMS OK" % len(arms) if ok else "BROKEN"))
    return 0 if ok else 1


def main(argv):
    if len(argv) >= 2 and argv[1] == '--selftest':
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            return selftest(td)
    if len(argv) < 2:
        print("usage: ordlist_check.py DUMP [DUMP...]\n"
              "       ordlist_check.py --selftest", file=sys.stderr)
        return 2
    rc = 0
    for path in argv[1:]:
        tot = dict(insns=0, ord=0, missing=0, extra=0, dup=0, trunc=0,
                   name=0)
        first = []

        def flush(pc, bm, lst, trunc):
            """Score ONE emitted record.

            The unit is the RECORD, not the pc.  A pc is translated many
            times in a run and each translation emits its own lines, so
            aggregating by pc merges independent records and reports every
            re-translation as a duplicate member -- which is what the first
            version of this checker did, and the 1,519 x86 'DUP's it printed
            were all that artefact.  df_emit() writes exactly one A line per
            record, at the end, so the A line is the boundary and it is exact.
            """
            if not bm and not lst and not trunc:
                return
            tot['insns'] += 1
            tot['ord'] += len(lst)
            tot['trunc'] += len(trunc)
            # Counted from the LIST, not from the de-duplicated set below,
            # so two entries naming the same register read as two.
            tot['name'] += sum(1 for e in lst if e[1] == 'name')
            if len(set(lst)) != len(lst):
                tot['dup'] += len(lst) - len(set(lst))
                if len(first) < 8:
                    first.append("DUP %s" % pc)
            S = set(lst)
            for m in bm:
                if m[0] in trunc:
                    continue
                if m not in S:
                    tot['missing'] += 1
                    if len(first) < 8:
                        first.append("MISSING %s %s" % (pc, m))
            for m in S:
                if m[1] == 'name':
                    # A SOURCE STATED BY NAME (INSN_DF_ORD_NAME) is
                    # LEGITIMATELY ABSENT FROM THE BITMAP, and this arm is
                    # the reason the aarch64 leg failed on `mrs x0,midr_el1`
                    # at 0x400c0c.  MIDR_EL1 is ARM_CP_CONST: it lives in the
                    # ARMCPU object, not CPUArchState, so it sets no bit in
                    # @rd and has no env range -- there is no D line for the
                    # bitmap to carry and there never can be.  Scoring it
                    # EXTRA said the translation stated a register it does
                    # not read, which is the opposite of the truth.  It is
                    # counted on its own row rather than merged into `ord`:
                    # a kind the bitmap cannot check is a kind this checker
                    # is NOT checking, and that has to be visible.
                    continue
                if m[1] in ('zeroreg', 'discard'):
                    continue      # the bitmap cannot express these
                if m[1] == 'unknown' or m not in bm:
                    tot['extra'] += 1
                    if len(first) < 8:
                        first.append("EXTRA %s %s" % (pc, m))

        bm, lst, trunc, cur = set(), [], set(), None
        with open(path) as f:
            for line in f:
                p_ = line.split()
                if not p_ or p_[0] not in ('D', 'O', 'A'):
                    continue
                cur = p_[1]
                if p_[0] == 'A':
                    flush(cur, bm, lst, trunc)
                    bm, lst, trunc = set(), [], set()
                    continue
                if p_[0] == 'D' and len(p_) >= 4:
                    d = p_[2]
                    if d not in ('r', 'w') or p_[3] == 'mem':
                        continue
                    kv = dict(x.split('=', 1) for x in p_[3:] if '=' in x)
                    if kv.get('reg', '?') != '?':
                        bm.add((d, 'global', kv['reg']))
                    else:
                        # (off, size), not off alone.  fields[] interns on
                        # the PAIR, and an instruction really can touch one
                        # offset at two widths -- x86 `fst` writes 16 bytes
                        # of an x87 slot and then 8 of it, two rows at
                        # off=928.  Keyed by offset alone the two collapse
                        # and the ordered list's second entry reads as a
                        # duplicate; 76 x86 rows said so.
                        bm.add((d, 'field', kv.get('off'), kv.get('size')))
                elif p_[0] == 'O' and len(p_) >= 4:
                    d = p_[2]
                    if p_[3] == 'truncated':
                        trunc.add(d)
                        continue
                    if len(p_) < 5:
                        continue
                    kind = p_[4] if '=' not in p_[4] else '?'
                    kv = dict(x.split('=', 1) for x in p_[5:] if '=' in x)
                    if kind == 'global':
                        lst.append((d, 'global', kv.get('reg')))
                    elif kind == 'field':
                        lst.append((d, 'field', kv.get('off'), kv.get('size')))
                    elif kind == 'discard':
                        lst.append((d, 'discard', kv.get('reg')))
                    elif kind == 'zeroreg':
                        lst.append((d, 'zeroreg', '-'))
                    elif kind == 'name':
                        lst.append((d, 'name', kv.get('reg')))
                    else:
                        lst.append((d, 'unknown', kind))
        flush(cur, bm, lst, trunc)

        vac = "OK" if (tot['ord'] > 0 and tot['insns'] > 0) else "VACUOUS"
        bad = tot['missing'] or tot['extra'] or tot['dup'] or vac != "OK"
        print("%s: records=%d ord_entries=%d MISSING=%d EXTRA=%d DUP=%d "
              "TRUNC=%d NAME=%d vacuity=%s -> %s"
              % (path, tot['insns'], tot['ord'], tot['missing'], tot['extra'],
                 tot['dup'], tot['trunc'], tot['name'], vac,
                 "FAIL" if bad else "PASS"))
        for s_ in first:
            print("    %s" % s_)
        if bad:
            rc = 1
    return rc

if __name__ == '__main__':
    sys.exit(main(sys.argv))
