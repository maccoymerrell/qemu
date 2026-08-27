#!/usr/bin/env python3
"""Emit the CP-H per-helper usage table as C, one .c.inc per target.

Every field name the reader derived is CHECKED BY THE COMPILER before it is
written down: a probe TU is built with the target's own compile command, and
a name that is not a member of CPUArchState makes it fail.  A row carrying one
is REFUSED WHOLE rather than trimmed -- trimming would delete an access that
may be real and turn an over-approximation into a missing dependency, which is
the error direction this project treats as disqualifying.

CHECKED ON EVERY TARGET THAT COMPILES THE FILE, not only on the one it is
named for.  The emitted .c.inc is included under a GUARD macro -- aarch64's
is TARGET_ARM -- and every configured target defining that macro compiles it.
Probing only the named target makes the verification scope narrower than the
consumption scope, and a field that exists on aarch64 and not on 32-bit arm
(env->keys, behind `#ifdef TARGET_AARCH64` in target/arm/cpu.h) then breaks
the build of a target nobody probed.

A field that is not a member on EVERY family target does not lose its row.
The family is partitioned by which targets have the field, and a guard macro
is DERIVED for that partition by reading the targets' own config-target.h --
never from a table in this file: the macro is accepted only when the set of
family targets defining it is exactly the set having the field.  When no
macro matches, the row is REFUSED WHOLE, which is the over-approximating
direction.
"""
import argparse, glob, json, os, re, shlex, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from preprocess import BUILD, entries_for

GUARD = {'x86_64': 'TARGET_I386', 'aarch64': 'TARGET_ARM',
         'riscv64': 'TARGET_RISCV', 'mipsel': 'TARGET_MIPS'}
LIB = {'x86_64': 'x86_64-linux-user', 'aarch64': 'aarch64-linux-user',
       'riscv64': 'riscv64-linux-user', 'mipsel': 'mipsel-linux-user'}
TDIR = {'x86_64': '/target/i386/', 'aarch64': '/target/arm/',
        'riscv64': '/target/riscv/', 'mipsel': '/target/mips/'}


def probe_cmd(isa, lib=None):
    for e in entries_for(lib or LIB[isa], lambda f: TDIR[isa] in f):
        if e['file'].endswith('cpu.c') or e['file'].endswith('helper.c'):
            return e
    raise SystemExit('no probe compile command for ' + (lib or LIB[isa]))


def _config_defines(lib):
    """The macro names a configured target's own config-target.h defines."""
    path = os.path.join(BUILD, lib + '-config-target.h')
    if not os.path.exists(path):
        return None
    names = set()
    for line in open(path):
        m = re.match(r'\s*#define\s+([A-Za-z_][A-Za-z_0-9]*)', line)
        if m:
            names.add(m.group(1))
    return names


def family_libs(isa):
    """Every configured target that COMPILES the file this isa emits.

    The file is included under GUARD[isa]; a target compiles it exactly when
    its own config-target.h defines that macro.  Read, never assumed.
    """
    guard, libs = GUARD[isa], []
    for path in sorted(glob.glob(os.path.join(BUILD, '*-config-target.h'))):
        lib = os.path.basename(path)[:-len('-config-target.h')]
        d = _config_defines(lib)
        if d and guard in d:
            libs.append(lib)
    if LIB[isa] not in libs:
        raise SystemExit('%s: own lib %s not in its own guard family %s'
                         % (isa, LIB[isa], guard))
    return libs


def derive_guard(isa, libs, present):
    """A macro whose defined-set over @libs is exactly @present, or None.

    Derived from the targets' own config-target.h.  Ambiguity is reported
    rather than resolved by preference: every matching macro is returned and
    the caller emits the first, naming the rest.
    """
    defs = {lib: (_config_defines(lib) or set()) for lib in libs}
    cands = set().union(*defs.values()) if defs else set()
    out = []
    for m in sorted(cands):
        if {lib for lib in libs if m in defs[lib]} == set(present):
            out.append(m)
    return out


def _components(expr):
    """Every member identifier in an access expression.

    `cp15.sctlr_el[1]` -> {'cp15', 'sctlr_el'}.  The compiler names the
    MEMBER it could not find, at whatever depth, so a row is matched against
    the rejected name by its components rather than by its whole text.
    Matching only the leading name made a family probe unable to drop
    `keys.apia` when `keys` is absent on 32-bit arm, and the generator exited
    "probe made no progress" instead of refusing the row.
    """
    return set(re.findall(r'[A-Za-z_][A-Za-z_0-9]*', expr))


def check_sizeof(isa, types, workdir, lib=None):
    """Type name -> sizeof, from the COMPILER, for the types it accepts.

    The extent of the state a POINTER ARGUMENT reaches is the size of what it
    points at, and the definition's own signature names that type.  Nothing
    here computes a size; a type the target's headers cannot size simply gets
    no entry, and the argument then states no extent -- which is what it did
    before this existed, for every non-gvec helper there is.
    """
    if not types:
        return {}
    e = probe_cmd(isa, lib)
    os.makedirs(workdir, exist_ok=True)
    tag = (lib or LIB[isa]).replace('-', '_')
    src = os.path.join(workdir, 'tprobe_%s.c' % tag)
    remaining = sorted(types)
    while True:
        with open(src, 'w') as f:
            f.write('#include "qemu/osdep.h"\n#include "cpu.h"\n')
            f.write('#include <stdio.h>\nint main(void){\n')
            for t in remaining:
                f.write('  printf("%s %zu\\n", "{t}", sizeof({t}));\n'
                        .format(t=t))
            f.write('  return 0;\n}\n')
        cmd = shlex.split(e['command'])
        out, i = [], 0
        while i < len(cmd):
            a = cmd[i]
            if a in ('-o', '-MQ', '-MF'):
                i += 2; continue
            if a in ('-c', '-MD', '-pipe', '-Werror'):
                i += 1; continue
            if a.endswith('.c'):
                out.append(src); i += 1; continue
            out.append(a); i += 1
        binp = os.path.join(workdir, 'tprobe_%s' % tag)
        out += ['-w', '-o', binp]
        r = subprocess.run(out, cwd=e['directory'], capture_output=True,
                           text=True)
        if r.returncode == 0:
            run = subprocess.run([binp], capture_output=True, text=True)
            res = {}
            for line in run.stdout.splitlines():
                n, sz = line.rsplit(' ', 1)
                res[n] = int(sz)
            return res
        bad = {t for t in remaining
               if re.search(r'\b%s\b' % re.escape(t.split()[-1]), r.stderr)}
        if not bad:
            return {}
        before = len(remaining)
        remaining = [x for x in remaining if x not in bad]
        if not remaining:
            return {}
        if len(remaining) == before:
            return {}


def check_fields(isa, fields, workdir, lib=None):
    """Return the subset of @fields that really are CPUArchState members.

    A field may be a member NAME or an ACCESS EXPRESSION with a constant
    subscript -- `regs[0]`.  The expression is what is offsetof'd, because
    the element is what the helper wrote and a range spanning the whole file
    reaches past every register in it and can be named as none of them.
    """
    e = probe_cmd(isa, lib)
    os.makedirs(workdir, exist_ok=True)
    tag = (lib or LIB[isa]).replace('-', '_')
    src = os.path.join(workdir, 'probe_%s.c' % tag)
    good = set()
    remaining = sorted(fields)
    while True:
        with open(src, 'w') as f:
            f.write('#include "qemu/osdep.h"\n#include "cpu.h"\n')
            f.write('#include <stdio.h>\nint main(void){\n')
            for i, fl in enumerate(remaining):
                f.write('  printf("%s %zu %zu\\n", "{n}", '
                        '(size_t)offsetof(CPUArchState, {n}), '
                        'sizeof(((CPUArchState *)0)->{n}));\n'.format(n=fl))
            f.write('  return 0;\n}\n')
        cmd = shlex.split(e['command'])
        out, i = [], 0
        while i < len(cmd):
            a = cmd[i]
            if a in ('-o', '-MQ', '-MF'):
                i += 2; continue
            if a in ('-c', '-MD', '-pipe', '-Werror'):
                i += 1; continue
            if a.endswith('.c'):
                out.append(src); i += 1; continue
            out.append(a); i += 1
        binp = os.path.join(workdir, 'probe_%s' % tag)
        out += ['-w', '-o', binp]
        r = subprocess.run(out, cwd=e['directory'], capture_output=True, text=True)
        if r.returncode == 0:
            run = subprocess.run([binp], capture_output=True, text=True)
            res = {}
            for line in run.stdout.splitlines():
                n, off, sz = line.split()
                res[n] = (int(off), int(sz))
            return res
        # gcc quotes the name with U+2018/U+2019 under a UTF-8 locale and
        # with ASCII apostrophes otherwise, and clang uses ASCII.  Matching
        # only the ASCII form made this branch unreachable in practice: the
        # first field that really was not a member did not get its row
        # refused, it made the generator exit with "named no member".
        q = "['\u2018\u2019`]"
        bad = set(re.findall(r"has no member named %s([A-Za-z_0-9]+)%s" % (q, q),
                             r.stderr))
        bad |= set(re.findall(r"no member named %s([A-Za-z_0-9]+)%s in" % (q, q),
                              r.stderr))
        # The compiler names the MEMBER; an expression that reaches it -- at
        # any depth, subscripted or not -- goes with it.
        bad |= {x for x in remaining if _components(x) & bad}
        if not bad:
            raise SystemExit('probe failed for %s (%s) and named no member:'
                             '\n%s' % (isa, lib or LIB[isa], r.stderr[-4000:]))
        before = len(remaining)
        remaining = [x for x in remaining if x not in bad]
        if len(remaining) == before:
            raise SystemExit('probe made no progress for ' + isa)


DIRNAME = {0: '0', 1: 'INSN_DF_RD', 2: 'INSN_DF_WR',
           3: 'INSN_DF_RD | INSN_DF_WR'}


def row_guard(v, field_guard, refuse):
    """The macro a row must be emitted under, '' for none, None to refuse.

    @field_guard maps a field to the macro that is true exactly where the
    field is a member.  A field that is a member everywhere is absent from
    it; a field that is a member somewhere but under no derivable macro is
    in @refuse, and takes its whole row with it.
    """
    need = set()
    for f in v['env']:
        if f in refuse:
            return None
        g = field_guard.get(f)
        if g:
            need.add(g)
    return ' && '.join('defined(%s)' % m for m in sorted(need))


def emit(isa, derived, extra_rows, offsets, out, field_guard=None,
         refuse_fields=None, family=None):
    field_guard = field_guard or {}
    refuse_fields = refuse_fields or {}
    rows, refused, guarded = [], [], []

    def take(name, v, hand=False):
        bad = [f for f in v['env'] if f not in offsets]
        if bad:
            refused.append((name, ('hand row names a non-member: %s' % bad)
                            if hand else
                            ('field(s) not members of CPUArchState: %s'
                             % ','.join(sorted(bad)))))
            return
        g = row_guard(v, field_guard, refuse_fields)
        if g is None:
            why = sorted(f for f in v['env'] if f in refuse_fields)
            refused.append((name, 'field(s) %s are members on only part of the '
                            '%s family and no config-target.h macro has '
                            'exactly that truth set'
                            % (','.join(why), GUARD[isa])))
            return
        v = dict(v, _guard=g)
        if g:
            guarded.append((name, g, sorted(f for f in v['env']
                                            if field_guard.get(f))))
        rows.append((name, v))

    #
    # A HAND ROW MERGES INTO THE DERIVED ROW OF THE SAME NAME; it does not
    # sit beside it.  The consumer looks a helper up by name and takes the
    # first match, so two rows spelled `raise_exception` would make one of
    # them dead -- silently, and with no way to tell which.  Merging keeps
    # BOTH statements: the mechanical reader's facts stay derived and stay
    # attributed to the lines it read them from, and the hand enumeration
    # ADDS the ones the reader could not reach.
    #
    # A FIELD THE TWO SIDES DISAGREE ABOUT IS A REFUSAL, not a precedence
    # question.  If the reader says a helper reads `error_code` and a hand
    # row says it writes it, one of them is wrong and picking either would
    # publish an unexamined guess -- so the row is refused whole and the
    # collision is named, which is the over-approximating direction this
    # file errs in everywhere else.
    #
    merged, collided = dict(extra_rows), []
    for name, v in sorted(derived['rows'].items()):
        if v['status'] != 'OK':
            if name not in merged:
                refused.append((name, v.get('why', v.get('status'))))
            continue
        h = merged.get(name)
        if h is None:
            take(name, v)
            continue
        bad = [f for f in set(v['env']) & set(h['env'])
               if v['env'][f] != h['env'][f]]
        if bad:
            collided.append((name, sorted(bad)))
            refused.append((name, 'hand row and derived row disagree about '
                            'the direction of %s' % ','.join(sorted(bad))))
            del merged[name]
            continue
        m = dict(v)
        m['env'] = dict(v['env'], **h['env'])
        m['env_where'] = dict(v.get('env_where', {}),
                              **h.get('env_where', {}))
        m['xlat'] = sorted(set(v.get('xlat', [])) | set(h.get('xlat', [])))
        m['argdir'] = dict(v.get('argdir', {}), **h.get('argdir', {}))
        m['hand_justification'] = h.get('hand_justification', '')
        m['_merged_from_derived'] = sorted(v['env'])
        merged[name] = m
    for name, v in sorted(merged.items()):
        take(name, v, hand=True)
    if collided:
        for name, bad in collided:
            print('%s: hand row %s REFUSED -- direction collision on %s'
                  % (isa, name, ','.join(bad)))

    w = out.write
    hand = set(merged)
    refused = [(n, why) for n, why in refused if n not in hand]
    w('/*\n * CP-H per-helper usage -- %s.  GENERATED, do not edit.\n'
      ' *\n'
      ' * Generator: contrib/plugins/champsim_tracer/tools/arc3_cov/\n'
      ' *            helper_usage/gen_table.py\n'
      ' * Subjects:  the helpers an OBSERVED run reached (the CP-H census,\n'
      ' *            QEMU_DF_HELPER_CENSUS), never a list from memory.\n'
      ' * Facts:     read off the PREPROCESSED body of each helper -- R5,\n'
      ' *            "if the information is in a macro body, expand the\n'
      ' *            macro" -- and every field name below was accepted by\n'
      ' *            offsetof(CPUArchState, ...) before it was written.\n'
      ' *\n' % isa)
    if family:
        w(' * Every field name was accepted on EVERY configured target that\n'
          ' * compiles this file (they define %s): %s.\n *\n'
          % (GUARD[isa], ', '.join(family)))
    if guarded:
        w(' * Rows emitted under a DERIVED guard -- the field is a member on\n'
          ' * only part of that family, and the macro named is the one whose\n'
          ' * truth set over the family is exactly the set that has it:\n')
        for n, g, fl in sorted(guarded):
            w(' *   %-22s %-26s %s\n' % (n, g, ','.join(fl)))
        w(' *\n')
    memrows = [(n, v['mem']) for n, v in rows if v.get('mem')]
    if memrows:
        w(' * CP1 -- helpers that perform GUEST MEMORY ACCESSES themselves.\n'
          ' * No qemu_ld/qemu_st op names these: the access happens inside\n'
          ' * the call, so without the row below QEMU\'s access list is SHORT\n'
          ' * for the instruction that called the helper.  Direction and the\n'
          ' * ADDRESS ARGUMENT are read off the call site; a count is NOT\n'
          ' * invented when the helper\'s access pattern is data-dependent.\n')
        for n, ms in sorted(memrows):
            for m in ms:
                w(' *   %-20s %-5s addr=%-4s data=%-4s %s\n'
                  % (n, {1: 'read', 2: 'write', 3: 'rmw'}[m['dir']],
                     'arg%d' % m['addr'] if m['addr'] is not None
                     else 'UNSTATED',
                     'arg%d' % m['data'] if m['data'] is not None
                     else '-',
                     'count unbounded' if m['unbounded'] else 'one access'))
        w(' *\n')
    w(' * Rows refused, and therefore still OVER-APPROXIMATED at run time:\n')
    if not refused:
        w(' *   (none)\n')
    for n, why in refused:
        w(' *   %-24s %s\n' % (n, why))
    if hand:
        w(' *\n * Rows the mechanical reader refused and a HAND enumeration '
          'supplies.\n * Each carries its justification in full:\n')
        for n in sorted(hand):
            j = merged[n].get('hand_justification', '')
            d = merged[n].get('_merged_from_derived')
            if d:
                j = ('MERGED with the row the mechanical reader DID derive '
                     'for this helper, whose fields (%s) keep their derived '
                     'citations above; the fields below are the hand '
                     'enumeration. ' % ', '.join(d)) + j
            w(' *   %s:\n' % n)
            line = ''
            for word in j.split():
                if len(line) + len(word) > 68:
                    w(' *     %s\n' % line)
                    line = ''
                line = (line + ' ' + word).strip()
            if line:
                w(' *     %s\n' % line)
    w(' */\n\n')

    for name, v in rows:
        if not v['env']:
            continue
        if v.get('_guard'):
            w('#if %s\n' % v['_guard'])
        w('static const DfHelperField dfu_%s_env[] = {\n' % name)
        unb = set(v.get('env_unbounded', []))
        for f, d in sorted(v['env'].items()):
            kind = 'DF_HF_XLAT' if f in v.get('xlat', []) else 'DF_HF_OPERAND'
            w('    { offsetof(CPUArchState, %s), '
              'sizeof(((CPUArchState *)0)->%s), %s, %s, %d },'
              '   /* %s%s */\n'
              % (f, f, DIRNAME[d], kind, 1 if f in unb else 0,
                 v.get('env_where', {}).get(f, ''),
                 ', INDEX NOT STATED' if f in unb else ''))
        w('};\n')
        if v.get('_guard'):
            w('#endif\n')
    for name, v in rows:
        if not v.get('mem'):
            continue
        if v.get('_guard'):
            w('#if %s\n' % v['_guard'])
        w('static const DfHelperAccess dfu_%s_acc[] = {\n' % name)
        for m in v['mem']:
            a = m['addr']
            d = m['data']
            w('    { %s, %s, %s, %d, %d },'
              '   /* %s, %d site(s) */\n'
              % (DIRNAME[m['dir']],
                 'DF_HA_NO_ARG' if a is None else str(a),
                 'DF_HA_NO_ARG' if d is None else str(d),
                 m['size'], 1 if m['unbounded'] else 0,
                 m['where'], m['n']))
        w('};\n')
        if v.get('_guard'):
            w('#endif\n')
    w('\nstatic const DfHelperUsage df_helper_usage[] = {\n')
    for name, v in rows:
        if v.get('_guard'):
            w('#if %s\n' % v['_guard'])
        ad = v.get('argdir', {})
        asz = v.get('argsize', {})
        dirs, sizes = [], []
        for k in range(8):
            x = ad.get(str(k), ad.get(k, 0))
            dirs.append(0 if x == 'env' else (x or 0))
            sizes.append(int(asz.get(str(k), asz.get(k, 0)) or 0))
        while dirs and dirs[-1] == 0:
            dirs.pop()
        while sizes and sizes[-1] == 0:
            sizes.pop()
        w('    { "%s", { %s }, { %s },\n'
          % (name, ', '.join(str(d) for d in dirs) or '0',
             ', '.join(str(z) for z in sizes) or '0'))
        if v['env']:
            w('      dfu_%s_env, ARRAY_SIZE(dfu_%s_env), true,\n'
              % (name, name))
        else:
            w('      NULL, 0, true,\n')
        w('      "%s",\n' % v.get('defined_at', '').replace('"', ''))
        if v.get('mem'):
            w('      dfu_%s_acc, ARRAY_SIZE(dfu_%s_acc) },\n' % (name, name))
        else:
            w('      NULL, 0 },\n')
        if v.get('_guard'):
            w('#endif\n')
    w('    { NULL, { 0 }, { 0 }, NULL, 0, false, NULL, NULL, 0 }\n};\n')
    return len(rows), refused, guarded


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--isa', required=True)
    ap.add_argument('--derived', required=True)
    ap.add_argument('--extra', help='hand-written rows, json')
    ap.add_argument('--workdir', required=True)
    ap.add_argument('-o', required=True)
    a = ap.parse_args()
    d = json.load(open(a.derived))
    extra = {}
    if a.extra and os.path.exists(a.extra):
        extra = json.load(open(a.extra)).get(a.isa, {})
    fields = set()
    for v in d['rows'].values():
        if v['status'] == 'OK':
            fields |= set(v['env'])
    for v in extra.values():
        fields |= set(v['env'])
    offs = check_fields(a.isa, fields, a.workdir)

    # THE EXTENT OF EACH POINTER ARGUMENT, from its declared pointee type.
    #
    # A gvec constructor tells the call site how wide its operands are; every
    # other helper told it nothing, so `helper_punpcklqdq_xmm(env, d, v, s)`
    # reached a vector register through an argument whose extent was 0 -- and
    # a range of unstated width names no register, which is why the wire's
    # XMM destinations had no QEMU write row.  The type the DEFINITION
    # declares is the fact; the compiler turns it into a size.
    types = set()
    for v in d['rows'].values():
        if v['status'] == 'OK':
            types |= set(v.get('argtype', {}).values())
    tsz = check_sizeof(a.isa, types, a.workdir)
    for v in d['rows'].values():
        if v['status'] != 'OK':
            continue
        ad = v.get('argdir', {})
        v['argsize'] = {}
        for k, t in v.get('argtype', {}).items():
            # tcg_env is not an operand: the env branch of the consumer
            # handles it through the member list and never asks for an
            # extent.  Emitting sizeof(CPUArchState) here would put a number
            # in the table that nothing reads and that does not fit the
            # field -- see the width check below.
            if ad.get(k, ad.get(str(k))) == 'env':
                continue
            if t not in tsz:
                continue
            # A SIZE THAT DOES NOT FIT IS NOT STATED.
            #
            # The field is 16 bits.  Truncating a wider one would publish an
            # extent SMALLER than the state the pointer reaches, and a short
            # extent is exactly what lets a range be resolved to the wrong
            # register -- the one error direction this table exists to avoid.
            # Reporting nothing leaves the argument where it was before this
            # column existed.
            if tsz[t] > 0xffff:
                continue
            v['argsize'][k] = tsz[t]

    # The file is compiled by every target defining GUARD[isa], not only by
    # the one it is named for.  Probe all of them and partition the fields by
    # where they are members; a field missing everywhere but here needs a
    # guard, and the guard is read off the targets' own config-target.h.
    libs = family_libs(a.isa)
    present = {f: set() for f in offs}
    for lib in libs:
        ok = check_fields(a.isa, set(offs), a.workdir, lib=lib)
        for f in ok:
            present[f].add(lib)
    field_guard, refuse_fields = {}, {}
    for f, where in sorted(present.items()):
        if set(where) == set(libs):
            continue
        cands = derive_guard(a.isa, libs, where)
        if cands:
            field_guard[f] = cands[0]
            if len(cands) > 1:
                print('%s: field %s guard %s (also exact: %s)'
                      % (a.isa, f, cands[0], ', '.join(cands[1:])))
        else:
            refuse_fields[f] = sorted(where)
            print('%s: field %s is a member on %s only and no macro matches '
                  '-- rows naming it are REFUSED' % (a.isa, f, sorted(where)))

    with open(a.o, 'w') as f:
        n, refused, guarded = emit(a.isa, d, extra, offs, f,
                                   field_guard=field_guard,
                                   refuse_fields=refuse_fields, family=libs)
    print('%s: %d rows written, %d refused, %d/%d field names accepted by '
          'offsetof on all %d %s targets (%d guarded, %d row(s) guarded)'
          % (a.isa, n, len(refused), len(offs), len(fields), len(libs),
             GUARD[a.isa], len(field_guard), len(guarded)))
