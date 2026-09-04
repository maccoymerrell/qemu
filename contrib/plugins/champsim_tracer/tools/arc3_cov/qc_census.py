#!/usr/bin/env python3
"""FPSR.QC's helper set, call-site set and STATEMENT COVERAGE, all read off
the PREPROCESSED target/arm sources (R5).

WHY THIS IS A SCRIPT AND NOT A LIST.  FPSR.QC is the cumulative saturation
bit.  QEMU raises it from inside env-taking helpers and through a pointer
handed to gvec helpers, and in neither case does an op name the bytes -- so
the register only reaches the wire because a translator says it does.  Which
translators owe that statement is a property of the EXPANSION: target/arm
writes its saturating helpers as macro families (DO_VMOVN_SAT, NEON_VOP_ENV)
and names them at the call sites by token pasting (gen_helper_mve_##FN##b).
A hand list of sites is stale the day a family gains a member, and a
raw-text grep for `gen_helper_<name>(` cannot see a pasted name at all.

WHAT IT REPORTS, and both directions matter:

  MISSING  a translator function that names a QC-reaching helper and states
           nothing -- the register the instruction exists to update is absent
           from the wire.  This is the defect PASS 69 measured as 9,408
           aarch64 encodings over 35 mnemonics.

  EXTRA    a translator function that states QC and names no QC-reaching
           helper -- a register on the wire for an instruction that does not
           touch it.  A fix for MISSING that is careless about which macro
           flavour it converts produces these, and a count of MISSING alone
           would call that success.

Both must be zero.  A run that cannot find its subject -- no compile
database, a TU that will not preprocess, an empty helper set -- REFUSES
rather than reporting zero, because a census that reports zero because it
looked at nothing is the silent false success this tree keeps relearning.

Usage:  QEMU_BUILD=<build> python3 qc_census.py [--verbose]

Author: Maccoy Merrell.
"""
import collections, json, os, re, sys, tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "helper_usage"))
import preprocess as P

#: The TUs whose expanded bodies are searched for the assignment itself.
BODY_FILES = ("neon_helper.c", "vec_helper.c", "helper-a64.c", "op_helper.c",
              "sve_helper.c", "mve_helper.c", "translate.c")

#: A definition header starts at a line break, OR on the same line directly
#: after a previous definition's closing brace -- which is where the second
#: and later members of a macro-generated family land.  Anchoring on '\n'
#: alone silently drops all but the first of each family.
DEFN = re.compile(
    r'(?:\n|\}[ \t]*)([A-Za-z_][^;{}()]*?)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}]*)\)\s*\n?\{')
#: cpp puts a `# <line> "<file>"` marker wherever a macro expansion crosses a
#: line -- including INSIDE a signature, because `bool` is one.  The markers
#: are what maps a site back to its source line, so they are stripped only for
#: the definition scan, never for the site scan.
LINEMARK = re.compile(r'^#[ \t].*$', re.M)


def strip_markers(txt):
    return LINEMARK.sub('', txt)
#: `} if (...) {` has the shape of a definition following a closing brace.
#: A C keyword in the name position is never a function name -- `} if (...) {`
#: has the shape of a definition following a closing brace, and a cast such as
#: `(void *)0` puts a type there.  A bogus node named `void` is not harmless:
#: nearly every function mentions it, so it becomes a hub that joins unrelated
#: parts of the graph and lets one function's statement answer for another's.
NOTFN = {"if", "while", "for", "switch", "else", "do", "return", "sizeof",
         "typeof", "__typeof__", "_Generic", "asm", "__asm__", "goto",
         "void", "char", "short", "int", "long", "float", "double", "signed",
         "unsigned", "const", "volatile", "static", "extern", "inline",
         "struct", "union", "enum", "typedef", "register", "restrict",
         "bool", "_Bool", "_Atomic", "__restrict", "__restrict__",
         "__attribute__", "__extension__", "case", "default", "break",
         "continue"}

QC_FIELD = re.compile(r'\bvfp\s*\.\s*qc\b')
CALLEE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
GENH = re.compile(r'\bgen_helper_([A-Za-z0-9_]+)\b')


def scan_defs(txt):
    """{name: [(params, body), ...]} for every top-level definition in txt."""
    out = collections.defaultdict(list)
    for m in DEFN.finditer(txt):
        fn, start = m.group(2), m.end()
        if fn in NOTFN:
            continue
        depth, i, n = 1, start, len(txt)
        while i < n and depth:
            c = txt[i]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
            i += 1
        out[fn].append((m.group(3), txt[start:i - 1]))
    return out


def split_args(s):
    """Top-level comma split of an argument list."""
    out, depth, cur = [], 0, []
    for c in s:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == ',' and depth == 0:
            out.append("".join(cur).strip()); cur = []
        else:
            cur.append(c)
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def calls_with_args(body, names):
    """Every call in `body` to one of `names`, as (name, [args])."""
    if not names:
        return
    for m in re.finditer(r'\b(%s)\s*\(' % "|".join(map(re.escape, sorted(names))),
                         body):
        i, depth = m.end(), 1
        while i < len(body) and depth:
            if body[i] == '(':
                depth += 1
            elif body[i] == ')':
                depth -= 1
            i += 1
        yield m.group(1), split_args(body[m.end():i - 1])


def main():
    verbose = "--verbose" in sys.argv
    out = tempfile.mkdtemp(prefix="qc_census")
    entries = P.entries_for("aarch64-linux-user", lambda f: "/target/arm/" in f)
    if not entries:
        sys.exit("REFUSE: no target/arm TUs in %s/compile_commands.json"
                 % P.BUILD)
    ipaths = {os.path.basename(e["file"]): P.preprocess(e, out) for e in entries}
    missing_tu = [f for f in BODY_FILES if f not in ipaths]
    if missing_tu:
        sys.exit("REFUSE: helper TUs absent from the build: %s" % missing_tu)

    # ---- the helper set ---------------------------------------------------
    bodies = collections.defaultdict(list)
    for name in BODY_FILES:
        src = strip_markers(open(ipaths[name], errors="replace").read())
        for fn, defs in scan_defs(src).items():
            bodies[fn].extend(b for _, b in defs)
    direct = {f for f, bs in bodies.items() if any(QC_FIELD.search(b) for b in bs)}
    if not direct:
        sys.exit("REFUSE: no function assigns env->vfp.qc -- the scan found "
                 "nothing, which is not the same as there being nothing")
    reach, changed = set(direct), True
    while changed:
        changed = False
        for f, bs in bodies.items():
            if f in reach:
                continue
            if any(c in reach for b in bs for c in CALLEE.findall(b)):
                reach.add(f); changed = True
    helpers = {f[len("helper_"):] for f in reach if f.startswith("helper_")}
    if not helpers:
        sys.exit("REFUSE: the QC-reaching set contains no helper_ function")
    print("QC-reaching helpers: %d  (direct assigners %d)"
          % (len(helpers), len(direct)))

    # ---- the emitters that take the fact as an argument -------------------
    src_tu = {b: strip_markers(open(ipaths[b], errors="replace").read())
              for b in ipaths if b.startswith("translate") or b == "gengvec.c"}
    trans = {b: scan_defs(t) for b, t in src_tu.items()}
    flagged = {}          # emitter name -> index of its `qc` parameter
    stating = set()       # every function whose own body states QC
    for tu, defs in trans.items():
        for fn, ds in defs.items():
            for params, body in ds:
                if "note_fpsr_qc" in body or QC_FIELD.search(body):
                    stating.add(fn)
                    args = split_args(params)
                    for i, p in enumerate(args):
                        if re.search(r'\bqc\s*$', p):
                            flagged[fn] = i
    if not flagged and not stating:
        sys.exit("REFUSE: no translator states FPSR.QC at all")
    print("emitters taking the fact as an argument: %d  %s"
          % (len(flagged), sorted(flagged)))

    # ---- the census -------------------------------------------------------
    #
    # ATTRIBUTED LOCALLY, AND THE LOCALITY IS THE POINT.  A per-lane wrapper
    # such as gen_sqshli_b names a QC-reaching helper and states nothing --
    # correctly, because the generator it calls, trunc_i64_env_imm, states it
    # once for the instruction.  So a function that NAMES a QC-reaching helper
    # is answered for when it states, or when something it calls states.  Its
    # CALLERS are not consulted: propagating up would let one saturating
    # instruction's statement answer for the whole decodetree dispatcher, and
    # a census that a dispatcher can satisfy measures nothing.
    #
    # The mirror question is asked the same way.  A function that states and
    # neither names a QC-reaching helper nor calls or is called by one that
    # does has put a register on the wire for an instruction that does not
    # touch it -- which is what a careless conversion of a macro flavour
    # produces, and what a count of MISSING alone would call success.
    PRIMS = {"note_fpsr_qc", "note_fpsr_qc_read", "note_fpsr_qc_write"}
    ID = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\b')
    missing, extra, covered = [], [], 0
    for tu, defs in sorted(trans.items()):
        node = {fn: "\n".join(b for _, b in ds)
                for fn, ds in defs.items() if fn not in PRIMS}
        # A file-scope TABLE or STRUCT of function pointers is how target/arm
        # hands an element function to an emitter -- f_vector_sqxtn[] and
        # f_scalar_sqshl alike; without them in the graph the element function
        # is invisible to the walk.
        for m in re.finditer(r'\n[A-Za-z_][^;{}()\n]*?\b([A-Za-z_]\w*)\s*'
                             r'(?:\[[^\]\n]*\])?\s*=\s*\{', src_tu[tu]):
            i, depth = m.end(), 1
            while i < len(src_tu[tu]) and depth:
                if src_tu[tu][i] == '{':
                    depth += 1
                elif src_tu[tu][i] == '}':
                    depth -= 1
                i += 1
            if m.group(1) in NOTFN:
                continue
            node[m.group(1)] = node.get(m.group(1), "") + src_tu[tu][m.end():i - 1]

        # TWO KINDS OF STATER, and the difference decides what a statement
        # answers for.  An UNCONDITIONAL one -- do_env_scalar1, gen_gvec_fn3_qc,
        # trunc_i64_env_imm -- states for every encoding that reaches it, so it
        # answers for the element functions handed to it as well as for itself.
        # A FLAG one -- a trans_ function passing `true` to a shared emitter --
        # states for its own instruction only.  Treating the two alike is what
        # let a decodetree dispatcher inherit a statement from any one of the
        # hundreds of trans_ functions it calls.
        names, direct, byflag = {}, set(), set()
        for fn, body in node.items():
            names[fn] = {h for h in GENH.findall(body) if h in helpers}
            if "note_fpsr_qc" in body and fn not in flagged:
                direct.add(fn)
            for callee, args in calls_with_args(body, flagged):
                idx = flagged[callee]
                if idx < len(args) and args[idx] in ("1", "true"):
                    byflag.add(fn)
        states = direct | byflag
        succ = {fn: {i for i in set(ID.findall(body)) if i in node and i != fn}
                for fn, body in node.items()}
        refs = collections.defaultdict(set)
        for g, ss in succ.items():
            for f in ss:
                refs[f].add(g)

        # THE WALK IS ROOT-DOWN, and the flag travels with the path.  A
        # function that names a QC-reaching helper is answered for when a
        # statement lies ON THE PATH THAT REACHED IT: above, in the emitter
        # that runs once per instruction and hands the element function to a
        # loop (do_2misc_narrow_scalar over gen_neon_narrow_sat_s8), or below,
        # in the generator it delegates to (gen_sqshli_b's trunc_i64_env_imm).
        # Both shapes are in target/arm and both are correct; what is not
        # correct is a path from the decodetree dispatcher to a saturating
        # helper with no statement anywhere along it.
        roots = [f for f in node if not refs[f]]
        seen = set()

        def walk(f, stated):
            if (f, stated) in seen:
                return
            seen.add((f, stated))
            # The flag that travels DOWN is only what the path has actually
            # stated.  The allowance for a statement BELOW f -- gen_sqshli_b
            # delegating to trunc_i64_env_imm -- answers for f alone and is
            # NOT propagated: a decodetree dispatcher calls hundreds of trans_
            # functions, and letting one of them that states answer for the
            # dispatcher would mark every other one covered.  That is exactly
            # how this census first read "0 missing" with a site reverted.
            onward = stated or f in states or any(g in direct for g in succ[f])
            if names[f]:
                ok = onward
                (covered_l if ok else missing).append((tu, f, sorted(names[f])))
            for g in sorted(succ[f]):
                walk(g, onward)

        covered_l = []
        sys.setrecursionlimit(20000)
        for r in sorted(roots):
            walk(r, False)
        # NOTHING IS LEFT UNVISITED.  A node the root walk never reached --
        # a decodetree entry point the dispatcher names through a table the
        # graph did not model, say -- would be neither covered nor missing,
        # and a census that answers "0 missing" about a function it never
        # looked at is the silent false success this tree keeps relearning.
        # Every such node is walked as a root of its own, unstated.
        for f in sorted(node):
            if (f, True) not in seen and (f, False) not in seen:
                walk(f, False)
        covered += len({(t, f) for t, f, _ in covered_l})
        missing[:] = [m for m in missing
                      if (m[0], m[1]) not in {(t, f) for t, f, _ in covered_l}]

        # The mirror question: a statement with no saturating helper under it.
        for fn in sorted(states):
            if QC_FIELD.search(node[fn]):
                # THE POINTER FORM.  gen_gvec_fn3_qc and do_int3_qc_vector_idx
                # compute &env->vfp.qc and hand it to a gvec helper, which
                # raises the bit through the pointer and so never names
                # env->vfp.qc itself.  The expander addressing the bytes IS
                # the evidence that a saturating helper is underneath.
                continue
            # An unconditional stater takes its helpers from the tables its
            # CALLERS hand it; a flag stater names them itself, and consulting
            # its callers there would let the dispatcher answer for it.
            frontier = list({fn} | refs[fn]) if fn in direct else [fn]
            hit, seen2 = False, set()
            while frontier and not hit:
                g = frontier.pop()
                if g in seen2:
                    continue
                seen2.add(g)
                if names.get(g):
                    hit = True
                    break
                frontier.extend(succ.get(g, ()))
            if not hit:
                extra.append((tu, fn))

    print("\nCOVERED  %d functions name a QC-reaching helper and the register "
          "is stated for it" % covered)
    print("MISSING  %d" % len(missing))
    for tu, fn, ns in sorted(missing):
        print("    %-20s %-32s %d helper(s): %s"
              % (tu, fn, len(ns), ", ".join(ns[:4])))
    print("EXTRA    %d" % len(extra))
    for tu, fn in sorted(extra):
        print("    %-20s %s" % (tu, fn))
    if verbose:
        json.dump({"helpers": sorted(helpers), "flagged": flagged,
                   "missing": missing,
                   "extra": extra},
                  open("qc_census.json", "w"), indent=1)
        print("\nwrote qc_census.json")
    return 1 if (missing or extra) else 0


if __name__ == "__main__":
    sys.exit(main())
