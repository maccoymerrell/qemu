#!/usr/bin/env python3
#
# Which rule the bytes reached, for a decoder made of switches.
#
# target/mips decodes its base ISA in a nest of hand-written switch statements,
# so there is no pattern line to write an identity on and no single table to
# key one off.  What there IS, at every leaf, is the `case OPC_*` label the
# switch dispatched on: that label IS the rule, stated by QEMU itself.
#
# This turns those labels into a table the decoder consults.  A call site in
# translate.c declares a site name and the expression the switch is about to
# dispatch on:
#
#     insn_df_mips_ident(MIPS_DF_SPECIAL, op1);
#     switch (op1) {
#     case OPC_SLL: ...
#
# and this script builds MIPS_DF_SPECIAL's row set FROM THAT SWITCH -- every
# case label in it, with the enumerator's value worked out from translate.h's
# and translate.c's own enum definitions, and the generic word from the
# checked-in adjudication data.  The call therefore cannot drift from the
# switch: if the two do not name the same expression, or the call is not
# immediately followed by a switch, generation fails.
#
# WHY BEFORE THE SWITCH AND NOT INSIDE EACH CASE.  A statement inside every
# case group would be some two thousand insertions in a file nobody could then
# read.  A value-keyed table read once, before the dispatch, says the same
# thing in one line -- PROVIDED the table holds only the labels that are
# instructions.
#
# WHICH IS THE OTHER HALF.  insn_dataflow_note_rule() is first-wins, and MIPS
# switches nest: `case OPC_SPECIAL:` merely reaches another switch, and if the
# outer table held that label it would state OPC_SPECIAL and the inner, real
# rule would lose.  So a case group whose body only DISPATCHES -- it contains
# a nested switch, or calls a function that itself contains an instrumented
# switch -- is left out of its site's table.  It is a table, not an
# instruction, and the honest thing for a table to state is nothing.  The
# classification is structural and computed here, not asserted: the set of
# dispatching functions is closed by iteration over the call graph.
#
# Author: Maccoy Merrell
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import os
import re
import sys

OPC_RE = r'(?:R6_|MMI_|TX79_)?OPC_[A-Z0-9_]+'


def strip_comments(text):
    """Blank the comments and KEEP the line structure.

    Line numbers are the only handle an error message has on the source, and
    a stripper that closes up multi-line comments makes every one of them
    point somewhere else.
    """
    text = re.sub(r'/\*.*?\*/',
                  lambda m: re.sub(r'[^\n]', ' ', m.group(0)),
                  text, flags=re.S)
    return re.sub(r'//[^\n]*', lambda m: ' ' * len(m.group(0)), text)


def object_macros(sources):
    """The arithmetic macros the encoding enumerators are written in terms of.

    target/mips spells its FPU opcodes as FOP(func, fmt), so the enumerator's
    value cannot be read without the macro.  Only single-line macros whose
    body is arithmetic are taken: anything with a call, a string or a
    statement in it is not an encoding and is left alone.
    """
    env = {}
    for lines in sources:
        for line in lines:
            m = re.match(r'#define\s+(\w+)\(([\w,\s]*)\)\s+(\S.*)$', line)
            if not m:
                continue
            name, params, body = m.group(1), m.group(2), m.group(3).strip()
            if not re.fullmatch(r'[()\s\w<>|&+\-*/~^]+', body):
                continue
            try:
                env[name] = eval('lambda %s: %s' % (params, body),
                                 {"__builtins__": {}}, {})
            except Exception:
                pass
    return env


def constant_macros(sources, env):
    """The object-like macros that carry an encoding, e.g. OPC_CP1."""
    out = {}
    for lines in sources:
        for line in lines:
            m = re.match(r'#define\s+(\w+)\s+(\S.*)$', line)
            if not m:
                continue
            name, body = m.group(1), m.group(2).strip()
            if not re.fullmatch(r'[()\s\w<>|&+\-*/~^]+', body):
                continue
            try:
                out[name] = eval(body, {"__builtins__": {}}, dict(env, **out))
            except Exception:
                pass
    return {k: v for k, v in out.items() if isinstance(v, int)}


def enum_values(sources):
    """Every enumerator the decoder defines, and its value.

    The expressions are shifts and ors over earlier enumerators and over the
    encoding macros, which is exactly what Python evaluates, so the values
    come from the source rather than from a second copy of the encoding.
    Every enumerator is taken, not just the OPC_ ones: an OPC_ value is
    routinely written in terms of a format or field constant that is not
    itself an opcode.
    """
    macros = object_macros(sources)
    vals = dict(macros)
    vals.update(constant_macros(sources, macros))
    #
    # Two passes, because the sources are read in a fixed order and an
    # enumerator may be written in terms of a constant a later file defines:
    # the FPU opcodes are FOP(func, FMT_S) in translate.c and FMT_S is in
    # translate.h.  A value that does not resolve on the second pass either
    # is not arithmetic or names something this script cannot see, and it
    # becomes residue rather than a wrong number.
    #
    for _ in range(2):
        for lines in sources:
            i = 0
            while i < len(lines):
                if re.match(r'^(?:typedef\s+)?enum\s*\w*\s*\{', lines[i]):
                    j = i + 1
                    while j < len(lines) and not lines[j].startswith('}'):
                        m = re.match(r'\s*(\w+)\s*=\s*(.+?),?\s*$', lines[j])
                        if m:
                            try:
                                vals[m.group(1)] = eval(m.group(2).rstrip(','),
                                                        {"__builtins__": {}},
                                                        dict(vals))
                            except Exception:
                                pass
                        j += 1
                    i = j
                i += 1
    opc = {k: v for k, v in vals.items()
           if re.fullmatch(OPC_RE, k) and isinstance(v, int)}
    if not opc:
        sys.exit('mips-df-ident: no OPC_ enumerators found -- the extraction '
                 'found nothing, which is a broken parse and not an empty '
                 'decoder')
    return opc


def function_owners(lines):
    """For each line, the name of the function it sits in."""
    owners = []
    cur = None
    for line in lines:
        m = re.match(r'^(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w \*]*?'
                     r'\b(\w+)\(', line)
        if m and not line.startswith(' '):
            cur = m.group(1)
        owners.append(cur)
    return owners


def switch_groups(lines, start, name):
    """The groups of the switch whose opening brace is on line `start`.

    A group is a run of case labels sharing one body.  Only labels at the
    switch's OWN depth belong to it: a nested switch's labels are that
    switch's, and attributing them here would put an inner rule in an outer
    table where a value collision or a wrong site is the best outcome.
    """
    groups = []
    labels = []
    body = []
    j = start + 1
    depth = 1
    while j < len(lines):
        s = lines[j]
        opens = s.count('{')
        closes = s.count('}')
        at_own_depth = (depth == 1)
        depth += opens - closes
        if depth <= 0:
            break
        if at_own_depth and re.search(r'case\s+[^:]*\.\.\.', s):
            sys.exit('translate.c:%d: %s: case ranges are not tabled; the '
                     'table is keyed by value and a range names no single '
                     'rule' % (j + 1, name))
        lm = re.findall(r'case\s+(%s)\s*:' % OPC_RE, s) if at_own_depth else []
        is_label = bool(re.match(r'\s*(case|default)\b', s)) and at_own_depth
        if lm or is_label:
            if body:                 # a new run of labels starts a new group
                groups.append((labels, body))
                labels, body = [], []
            labels += lm
            if is_label and not lm:
                # a label this table cannot key on; the group is still a group
                labels += ['?']
        else:
            if labels or body:
                body.append(s)
        j += 1
    if labels or body:
        groups.append((labels, body))

    #
    # A group that falls through belongs to the group it falls into.  MIPS
    # writes `case OPC_PS_FMT: check_ps(ctx); /* fall through */` above the
    # group that actually emits, and reading the two apart would let a label
    # whose real body dispatches look like one that emits.
    #
    merged = []
    carried = []
    for labels, body in groups:
        text = ' '.join(body)
        labels = carried + labels
        carried = []
        if body and not re.search(r'\b(break|return|continue|goto)\b'
                                  r'|g_assert_not_reached', text):
            carried = labels
            continue
        merged.append((labels, body))
    if carried:
        merged.append((carried, []))
    return merged


def find_sites(lines, path):
    """Each site, the switch its calls name, and that switch's groups.

    A site's table is built from the switch that dispatches on the expression
    the call names, in the function the call sits in.  The call need not be
    the line before the switch: a site may be consulted a second time on a
    path that returns before the dispatch is reached -- MIPS spells its no-op
    as a shift into $zero, and QEMU's shift emitters return at that test --
    and every such call must reach the same table.  What is checked is that
    the expression names exactly one switch in the call's own function, so
    the table cannot silently come from somewhere the call does not.
    """
    owners = function_owners(lines)
    calls = {}
    for i, line in enumerate(lines):
        m = re.match(r'\s*insn_df_mips_ident\(MIPS_DF_(\w+),\s*(.+?)\);\s*$',
                     line)
        if not m:
            continue
        name, ctrl = m.group(1), m.group(2).strip()
        func = owners[i]
        calls.setdefault(name, []).append((i, ctrl, func))

    sites = []
    for name, cs in calls.items():
        ctrls = {c[1] for c in cs}
        funcs = {c[2] for c in cs}
        if len(ctrls) != 1 or len(funcs) != 1:
            sys.exit('%s: MIPS_DF_%s is called on %s in %s; one site is one '
                     'switch' % (path, name, sorted(ctrls), sorted(funcs)))
        ctrl = ctrls.pop()
        func = cs[0][2]
        found = set()
        for i, _, _ in cs:
            j = i
            while j < len(lines) and owners[j] == func:
                sw = re.match(r'\s*switch \((.+)\) \{\s*$', lines[j])
                if sw and sw.group(1).strip() == ctrl:
                    found.add(j)
                    break
                j += 1
            else:
                sys.exit('%s:%d: MIPS_DF_%s names %r and no switch below it '
                         'in %s dispatches on that; the table is built from '
                         'the switch, so a call that names none has no '
                         'subject' % (path, i + 1, name, ctrl, func))
        if len(found) != 1:
            sys.exit('%s:%d: MIPS_DF_%s\'s calls reach %d different switches '
                     'on %r; one site is one table'
                     % (path, cs[0][0] + 1, name, len(found), ctrl))
        sw_line = found.pop()
        sites.append({'line': cs[0][0] + 1, 'name': name, 'ctrl': ctrl,
                      'switch': sw_line, 'func': func,
                      'groups': switch_groups(lines, sw_line, name)})

    seen = {}
    for s in sites:
        if s['switch'] in seen:
            sys.exit('%s:%d: MIPS_DF_%s and MIPS_DF_%s reach the same switch; '
                     'two sites cannot both be one table\'s'
                     % (path, s['switch'] + 1, seen[s['switch']], s['name']))
        seen[s['switch']] = s['name']
    return sites


def dispatching_functions(sites):
    """Functions that contain an instrumented switch, closed over calls.

    A group calling one of these reaches another table, so its own label is a
    table's name and states nothing.
    """
    funcs = {s['func'] for s in sites if s['func']}
    changed = True
    while changed:
        changed = False
        for s in sites:
            for labels, body in s['groups']:
                text = '\n'.join(body)
                if 'switch (' in text or any(f + '(' in text for f in funcs):
                    if s['func'] and s['func'] not in funcs:
                        funcs.add(s['func'])
                        changed = True
    return funcs


def load_vocabulary(path):
    voc = {}
    with open(path) as f:
        for line in f:
            m = re.match(r'#define\s+(INSN_DF_WORD_\w+)\s+"([a-z0-9.]+)"', line)
            if m:
                voc[m.group(2)] = m.group(1)
    if not voc:
        sys.exit('mips-df-ident: no words defined in %s' % path)
    return voc


def load_words(path, voc):
    rows = {}
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip('\n')
            if not line or line.startswith('#'):
                continue
            p = line.split('\t')
            if len(p) < 2:
                sys.exit('%s:%d: expected rule<TAB>word' % (path, n))
            rule, word = p[0], p[1]
            if rule in rows:
                sys.exit('%s:%d: %s stated twice' % (path, n, rule))
            if word == '-':
                if len(p) < 3 or not p[2].strip():
                    sys.exit('%s:%d: %s states no word and gives no reason'
                             % (path, n, rule))
                rows[rule] = None
            elif word in voc:
                rows[rule] = voc[word]
            else:
                sys.exit('%s:%d: %s: unknown generic word %r'
                         % (path, n, rule, word))
    if not rows:
        sys.exit('mips-df-ident: %s has no rows' % path)
    return rows


def main():
    ap = argparse.ArgumentParser(
        description='the rule each MIPS case label names, as a table')
    ap.add_argument('source', help='target/mips/tcg/translate.c')
    ap.add_argument('words', help='the adjudication data')
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--vocabulary', required=True)
    ap.add_argument('--enums', action='append', default=[],
                    help='further sources defining OPC_ enumerators')
    ap.add_argument('--residue', help='write the untabled labels here')
    args = ap.parse_args()

    lines = strip_comments(open(args.source).read()).split('\n')
    enums = [lines] + [strip_comments(open(p).read()).split('\n')
                       for p in args.enums]
    vals = enum_values(enums)
    voc = load_vocabulary(args.vocabulary)
    words = load_words(args.words, voc)

    sites = find_sites(lines, args.source)
    if not sites:
        sys.exit('mips-df-ident: %s has no call sites -- a table with no '
                 'consult is not a statement' % args.source)
    disp = dispatching_functions(sites)

    missing, residue, used = [], [], set()
    out_sites = []
    for s in sites:
        rows = {}
        for labels, body in s['groups']:
            text = '\n'.join(body)
            dispatches = ('switch (' in text
                          or any(f + '(' in text for f in disp))
            for l in labels:
                if l == '?':
                    continue
                if dispatches:
                    residue.append('%s\tDISPATCHER\t%s' % (l, s['name']))
                    continue
                if l not in vals:
                    residue.append('%s\tNO-VALUE\t%s' % (l, s['name']))
                    continue
                if l not in words:
                    missing.append(l)
                    continue
                used.add(l)
                v = vals[l] & 0xffffffff
                if v in rows and rows[v][0] != l:
                    sys.exit('mips-df-ident: %s: %s and %s share value '
                             '0x%08x; one table cannot answer for both'
                             % (s['name'], rows[v][0], l, v))
                rows[v] = (l, words[l])
        out_sites.append((s['name'], rows))

    if missing:
        sys.exit('mips-df-ident: %s: these case labels have no adjudicated '
                 'word: %s' % (args.words, ' '.join(sorted(set(missing)))))
    unused = sorted(set(words) - used)
    if unused:
        sys.exit('mips-df-ident: %s: these rows are adjudicated for a label '
                 'no instrumented switch dispatches on: %s'
                 % (args.words, ' '.join(unused)))

    o = ['/*',
         ' * Generated by scripts/mips-df-ident.py from',
         ' * %s and' % args.source,
         ' * %s -- do not edit.' % args.words,
         ' *',
         ' * One table per dispatch site, holding the case labels of the',
         ' * switch that site precedes: the rule each label names and the',
         ' * generic word it carries.  Labels whose body only reaches another',
         ' * table are absent on purpose -- a table states no rule, and',
         ' * insn_dataflow_note_rule() is first-wins.',
         ' */',
         'typedef enum {']
    for name, _ in out_sites:
        o.append('    MIPS_DF_%s,' % name)
    o += ['    MIPS_DF_NSITES',
          '} MipsDfSite;',
          '',
          'typedef struct MipsDfRow {',
          '    uint32_t value;',
          '    const char *rule;',
          '    const char *word;',
          '} MipsDfRow;',
          '']
    total = 0
    for name, rows in out_sites:
        o.append('static const MipsDfRow mips_df_rows_%s[] = {' % name)
        for v in sorted(rows):
            rule, word = rows[v]
            o.append('    { 0x%08xu, "%s", %s },'
                     % (v, rule, word if word else 'NULL'))
            total += 1
        o.append('};')
    o += ['',
          'static const MipsDfRow * const mips_df_site_rows[] = {']
    for name, _ in out_sites:
        o.append('    mips_df_rows_%s,' % name)
    o += ['};',
          'static const unsigned mips_df_site_n[] = {']
    for name, rows in out_sites:
        o.append('    %d,' % len(rows))
    o += ['};',
          '',
          'static void insn_df_mips_ident(MipsDfSite site, uint32_t v)',
          '{',
          '    const MipsDfRow *rows = mips_df_site_rows[site];',
          '    unsigned lo = 0, hi = mips_df_site_n[site];',
          '',
          '    while (lo < hi) {',
          '        unsigned mid = (lo + hi) / 2;',
          '',
          '        if (rows[mid].value == v) {',
          '            insn_dataflow_note_rule(rows[mid].rule);',
          '            insn_dataflow_note_word(rows[mid].word);',
          '            return;',
          '        }',
          '        if (rows[mid].value < v) {',
          '            lo = mid + 1;',
          '        } else {',
          '            hi = mid;',
          '        }',
          '    }',
          '}',
          '']

    tmp = args.output + '.tmp'
    with open(tmp, 'w') as f:
        f.write('\n'.join(o))
    os.replace(tmp, args.output)

    if args.residue:
        with open(args.residue, 'w') as f:
            f.write('# label\twhy\tsite\n')
            f.write('\n'.join(sorted(set(residue))) + '\n')
    print('mips-df-ident: %d sites, %d rows, %d labels not tabled'
          % (len(out_sites), total, len(set(residue))), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
