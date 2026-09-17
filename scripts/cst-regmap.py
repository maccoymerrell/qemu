#!/usr/bin/env python3
#
# The map from a QEMU register NAME to the generic register the trace publishes.
#
# The dataflow ABI hands a consumer a provenance bit and, for the bits that
# stand for storage, a NAME: the string the target passed to
# tcg_global_mem_new(), or the string it passed to
# insn_dataflow_declare_regfile().  Those names are the target's own spelling --
# "at" and "v0" on MIPS, "x0/zero" on RISC-V, "lr" for AArch64's X30 -- and the
# wire publishes a generic identifier instead.  Something has to join the two,
# and that something must be complete, because a name with no row is a register
# the trace cannot name at all.
#
# So this generator does not take the name universe on trust.  It reads it out
# of the target's own sources -- every tcg_global_mem_new*() call and every
# insn_dataflow_declare_regfile() call in the files that register them -- and
# joins that universe against the checked-in adjudication table.  The join
# REFUSES IN BOTH DIRECTIONS:
#
#   * a name the target registers that the table does not carry is a GAP, and
#   * a table row naming no registered name is a DEAD RULE,
#
# and either one fails generation, which fails the build.  A table that is
# quietly short would publish REG_NONE for a real register and nothing would
# say so; a table with a dead row would look like coverage it does not have.
#
# The scrape is deliberately brittle in the one direction that is safe: a call
# whose third argument is a shape this file does not recognise is an ERROR, not
# a skip.  A target that grows a new way of naming a register breaks the build
# rather than losing the register.
#
# Author: Maccoy Merrell

import argparse
import os
import re
import sys


# The targets this plugin supports, and the files that register their
# registers.  A file listed here is read in full; a tcg_global_mem_new call
# anywhere else in the target is not reachable from these and would be missed,
# so the last entry of each list is checked: see check_no_stray_sites().
TARGETS = {
    'x86_64': {
        'dir': 'target/i386',
        'files': ['target/i386/tcg/translate.c'],
        'defines': {'TARGET_X86_64': True},
    },
    'aarch64': {
        'dir': 'target/arm',
        'files': ['target/arm/tcg/translate.c', 'target/arm/tcg/translate-a64.c'],
        'defines': {'TARGET_AARCH64': True},
    },
    'riscv64': {
        'dir': 'target/riscv',
        'files': ['target/riscv/translate.c'],
        'defines': {},
    },
    'mipsel': {
        'dir': 'target/mips',
        'files': ['target/mips/tcg/translate.c',
                  'target/mips/tcg/msa_translate.c',
                  'target/mips/tcg/mxu_translate.c'],
        'defines': {},
    },
}

# The SECOND namespace: the names QEMU's gdbstub registers.
#
# The value-read route does not go through a TCG global's name.  It goes
# through qemu_plugin_get_registers(), whose descriptors carry the (feature,
# name) pair the target's gdbstub publishes -- and that is a DIFFERENT
# spelling of the same register file: AArch64's X30 is "lr" to TCG and "x30"
# to gdb, RISC-V's x1 is "x1/ra" to TCG and "ra" to gdb, and the program
# counter is a TCG global on neither of them while gdb names it on both.
#
# So the map is read out of the target's own registration site again, and for
# the gdbstub that site is the feature XML the target hands gdb: every
# <reg name="..."> inside the <feature name="..."> the CORE file declares.
# Scope is the CORE feature per target and is stated here rather than
# discovered: the optional features (FPU, SVE, MTE, the RISC-V CSR set) are
# registered dynamically and per-CPU, and a namespace whose membership
# depends on the CPU model cannot be joined at BUILD time.  A register in one
# of those keeps whatever route it already had; nothing here removes one.
GDB_TARGETS = {
    'x86_64':  {'files': ['gdb-xml/i386-64bit.xml']},
    'aarch64': {'files': ['gdb-xml/aarch64-core.xml']},
    'riscv64': {'files': ['gdb-xml/riscv-64bit-cpu.xml']},
    'mipsel':  {'files': ['gdb-xml/mips-cpu.xml']},
}

FEATURE_RE = re.compile(r'<feature\s+name="([^"]+)"')
XMLREG_RE = re.compile(r'<reg\s+name="([^"]+)"')


def scrape_gdb(root, isa):
    """(name -> feature) for every register the CORE feature file declares.

    Brittle in the safe direction: a file with no <feature> line, or with
    more than one, is an ERROR rather than a partial read, because both
    shapes mean the scrape no longer describes the file it is reading.
    """
    universe = {}
    for rel in GDB_TARGETS[isa]['files']:
        text = read(os.path.join(root, rel))
        feats = FEATURE_RE.findall(text)
        if len(feats) != 1:
            raise SystemExit(
                'cst-regmap: %s: %s declares %d features, expected exactly 1'
                % (isa, rel, len(feats)))
        names = XMLREG_RE.findall(text)
        if not names:
            raise SystemExit('cst-regmap: %s: %s declares no registers'
                             % (isa, rel))
        for n in names:
            if n in universe:
                raise SystemExit('cst-regmap: %s: %s names %r twice'
                                 % (isa, rel, n))
            universe[n] = feats[0]
    return universe


CALL_RE = re.compile(r'\btcg_global_mem_new(?:_i32|_i64|_ptr)?\s*\(')
DECL_RE = re.compile(r'\binsn_dataflow_declare_regfile\s*\(')

STR_ARRAY_RE_TMPL = (
    r'const\s+char\s*(?:\*\s*)?(?:const\s*)?{name}\s*'
    r'\[[^;=]*=\s*\{{(?P<body>.*?)\}}\s*;'
)
STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def strip_comments(text):
    """
    Blank out comments, preserving every byte position and newline.

    Positions are preserved because the scrape reports line numbers back to
    the reader, and a reader sent to the wrong line would be worse than no
    line at all.  Comments must go: mxu_translate.c explains the registration
    in prose that names tcg_global_mem_new(), and a scanner that read prose as
    a call refused a target that was in fact complete.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            j = text.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(''.join('\n' if ch == '\n' else ' '
                               for ch in text[i:j]))
            i = j
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            j = text.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
            continue
        if c == '"' or c == "'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == '\\' else 1
            out.append(text[i:min(j + 1, n)])
            i = j + 1
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def read(path):
    with open(path, 'r', encoding='utf-8') as f:
        return strip_comments(f.read())


def split_args(text, start):
    """Split the argument list of a call whose '(' is at text[start]."""
    assert text[start] == '('
    depth = 0
    args = []
    cur = []
    i = start
    while i < len(text):
        c = text[i]
        if c == '(':
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif c == ')':
            depth -= 1
            if depth == 0:
                args.append(''.join(cur).strip())
                return args, i + 1
        elif c == ',' and depth == 1:
            args.append(''.join(cur).strip())
            cur = []
            i += 1
            continue
        elif c == '"':
            j = i + 1
            while j < len(text) and text[j] != '"':
                j += 2 if text[j] == '\\' else 1
            cur.append(text[i:j + 1])
            i = j + 1
            continue
        cur.append(c)
        i += 1
    raise ValueError('unterminated call')


def find_array(root, target_dir, name, here=None):
    """
    Find a string array's elements, in source order, or None.

    The file that holds the call is searched FIRST and the rest only if it has
    no definition.  Two targets spell the same array name in two files --
    target/arm's translate.c and translate-a64.c both define `regnames`, one
    holding r0..r14 and the other x0..x29,lr,sp -- so a search that took the
    first match anywhere returned the AArch32 file for the AArch64 call and
    the whole X register file went unscraped.
    """
    rx = re.compile(STR_ARRAY_RE_TMPL.format(name=re.escape(name)), re.S)
    if here is not None:
        m = rx.search(read(os.path.join(root, here)))
        if m:
            return [s for s in STRING_RE.findall(m.group('body'))]

    found = {}
    seen = set()
    for base in [os.path.join(root, target_dir)]:
        for dirpath, _dirs, files in os.walk(base):
            for fn in files:
                if not (fn.endswith('.c') or fn.endswith('.h')
                        or fn.endswith('.c.inc')):
                    continue
                path = os.path.join(dirpath, fn)
                if path in seen:
                    continue
                seen.add(path)
                m = rx.search(read(path))
                if m:
                    found[os.path.relpath(path, root)] = [
                        s for s in STRING_RE.findall(m.group('body'))]
    if len(found) > 1:
        raise SystemExit(
            'cst-regmap: %s is defined in %s and the call site does not '
            'define it.\n  Picking one silently is how the AArch64 X file '
            'went unscraped behind AArch32\'s array of the same name.'
            % (name, ', '.join(sorted(found))))
    return next(iter(found.values())) if found else None


def resolve_name_arg(root, tdir, text, arg, defines, where, here=None):
    """
    The names a third argument to tcg_global_mem_new() can stand for.

    Returns a list, because an array subscript stands for the whole array: the
    loop bound is not evaluated here on purpose.  Over-approximating the
    universe is the safe direction for a table -- it demands a row for a name
    that a particular CPU model may never register -- and under-approximating
    is not, because it would let a real name through with no row.
    """
    arg = arg.strip()

    m = STRING_RE.fullmatch(arg)
    if m:
        return [m.group(1)]

    # A macro that expands to one string literal, spelled once in the file.
    m = re.fullmatch(r'[A-Z][A-Z0-9_]*', arg)
    if m:
        vals = macro_strings(text, arg)
        if vals is None:
            raise SystemExit(
                'cst-regmap: %s: macro %s does not expand to a string literal'
                % (where, arg))
        return vals

    # ARRAY[expr]
    m = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)\s*\[.*\]', arg, re.S)
    if m:
        arr = find_array(root, tdir, m.group(1), here)
        if arr is None:
            raise SystemExit('cst-regmap: %s: no string array named %s'
                             % (where, m.group(1)))
        return arr

    # A local g_autofree built by g_strdup_printf("<fmt>", ARRAY[expr]).
    m = re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', arg)
    if m:
        vals = strdup_names(root, tdir, text, arg, where, here)
        if vals is not None:
            return vals

    raise SystemExit(
        'cst-regmap: %s: unrecognised register-name argument %r.\n'
        '  A new way of naming a register fails generation on purpose: the\n'
        '  alternative is a register the map silently cannot name.' %
        (where, arg))


def macro_strings(text, macro):
    """
    Every string a #define of @macro stands for.

    ALL of them, not the one this build selects: a macro spelled twice under
    an #ifdef (x86's "rip" and "eip") names two registers the same map can
    carry, and demanding a row for both is the same safe over-approximation an
    array subscript already gets.  Choosing one would make the table depend on
    which target the generator thought it was reading.
    """
    out = [STRING_RE.findall(m.group(1))[0]
           for m in re.finditer(r'^\s*#\s*define\s+%s\s+("(?:[^"\\]|\\.)*")\s*$'
                                % re.escape(macro), text, re.M)]
    return out or None


def strdup_names(root, tdir, text, var, where, here=None):
    """Names built as g_strdup_printf("<fmt>", ARRAY[expr])."""
    rx = re.compile(r'\b%s\s*=\s*g_strdup_printf\s*\(' % re.escape(var))
    m = rx.search(text)
    if m is None:
        return None
    args, _ = split_args(text, text.index('(', m.end() - 1))
    fmt = STRING_RE.fullmatch(args[0].strip())
    if fmt is None or fmt.group(1).count('%') != 1 or '%s' not in fmt.group(1):
        raise SystemExit('cst-regmap: %s: %s is built by a format this '
                         'generator cannot expand' % (where, var))
    inner = resolve_name_arg(root, tdir, text, args[1], {}, where, here)
    return [fmt.group(1).replace('%s', n) for n in inner]


def scrape(root, isa):
    """Every register name the target can register, with where it came from."""
    spec = TARGETS[isa]
    universe = {}

    for rel in spec['files']:
        path = os.path.join(root, rel)
        text = read(path)

        for m in CALL_RE.finditer(text):
            open_paren = text.index('(', m.end() - 1)
            args, _ = split_args(text, open_paren)
            where = '%s:%d' % (rel, text[:m.start()].count('\n') + 1)
            if len(args) != 3:
                raise SystemExit('cst-regmap: %s: tcg_global_mem_new with %d '
                                 'arguments' % (where, len(args)))
            for name in resolve_name_arg(root, spec['dir'], text, args[2],
                                         spec['defines'], where, rel):
                universe.setdefault(name, where)

        for m in DECL_RE.finditer(text):
            open_paren = text.index('(', m.end() - 1)
            args, _ = split_args(text, open_paren)
            where = '%s:%d' % (rel, text[:m.start()].count('\n') + 1)
            if len(args) != 5:
                raise SystemExit('cst-regmap: %s: declare_regfile with %d '
                                 'arguments' % (where, len(args)))
            arr = find_array(root, spec['dir'], args[0].strip(), rel)
            if arr is None:
                raise SystemExit('cst-regmap: %s: no string array named %s'
                                 % (where, args[0].strip()))
            for name in arr:
                universe.setdefault(name, where)

    return universe


def check_no_stray_sites(root, isa):
    """
    A registration site outside the files this generator reads.

    The file list is the generator's own assumption, and an assumption that
    can go stale silently is the shape this tree keeps paying for.  So the
    whole target directory is swept for the two calls and anything outside the
    list is an error.
    """
    spec = TARGETS[isa]
    listed = set(spec['files'])
    stray = []
    for dirpath, _dirs, files in os.walk(os.path.join(root, spec['dir'])):
        for fn in files:
            if not (fn.endswith('.c') or fn.endswith('.c.inc')):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            if rel in listed:
                continue
            text = read(path)
            if CALL_RE.search(text) or DECL_RE.search(text):
                stray.append(rel)
    if stray:
        raise SystemExit(
            'cst-regmap: %s registers registers in files this generator does '
            'not read: %s\n  Add them to TARGETS[%r][\'files\'].'
            % (isa, ', '.join(sorted(stray)), isa))


def read_tsv(path):
    rows = []
    with open(path, 'r', encoding='utf-8') as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip('\n')
            if not line or line.lstrip().startswith('#'):
                continue
            parts = line.split('\t')
            if len(parts) != 3:
                raise SystemExit('%s:%d: expected 3 tab-separated columns, '
                                 'got %d' % (path, lineno, len(parts)))
            name, reg, ground = (p.strip() for p in parts)
            if not re.fullmatch(r'REG_[A-Z0-9_]+', reg):
                raise SystemExit('%s:%d: %r is not a REG_* identifier'
                                 % (path, lineno, reg))
            if not ground:
                raise SystemExit('%s:%d: %s has no stated ground'
                                 % (path, lineno, name))
            rows.append((name, reg, ground, lineno))
    return rows


def c_string(s):
    return '"%s"' % s.replace('\\', '\\\\').replace('"', '\\"')


def emit(isa, rows, out):
    guard = 'CHAMPSIM_TRACER_REGMAP_%s_H' % isa.upper()
    lines = []
    lines.append('/*')
    lines.append(' * GENERATED by scripts/cst-regmap.py from')
    lines.append(' * contrib/plugins/champsim_tracer/regmap/%s.tsv.' % isa)
    lines.append(' * DO NOT EDIT: change the TSV or the generator.')
    lines.append(' *')
    lines.append(' * Sorted by name so the lookup can bisect, and the order is')
    lines.append(' * asserted at install time rather than assumed.')
    lines.append(' */')
    lines.append('#ifndef %s' % guard)
    lines.append('#define %s' % guard)
    lines.append('')
    lines.append('static const CstRegMapRow cst_regmap_%s[] = {' % isa)
    for name, reg, ground, _ in sorted(rows, key=lambda r: r[0]):
        lines.append('    { %s, %s },  /* %s */' % (c_string(name), reg, ground))
    lines.append('};')
    lines.append('')
    lines.append('#endif /* %s */' % guard)
    lines.append('')
    text = '\n'.join(lines)
    with open(out, 'w', encoding='utf-8') as f:
        f.write(text)


def emit_gdb(isa, rows, feature_of, out):
    guard = 'CHAMPSIM_TRACER_GDBMAP_%s_H' % isa.upper()
    lines = []
    lines.append('/*')
    lines.append(' * GENERATED by scripts/cst-regmap.py --namespace gdb from')
    lines.append(' * contrib/plugins/champsim_tracer/regmap/%s.gdb.tsv.' % isa)
    lines.append(' * DO NOT EDIT: change the TSV or the generator.')
    lines.append(' *')
    lines.append(' * The gdbstub spelling of this target\'s CORE register')
    lines.append(' * feature, joined to the wire\'s generic ids.  This is the')
    lines.append(' * namespace qemu_plugin_get_registers() hands a plugin, so')
    lines.append(' * it is the namespace a VALUE READ resolves through.')
    lines.append(' */')
    lines.append('#ifndef %s' % guard)
    lines.append('#define %s' % guard)
    lines.append('')
    lines.append('static const CstGdbMapRow cst_gdbmap_%s[] = {' % isa)
    for name, reg, ground, _ in sorted(rows, key=lambda r: r[0]):
        lines.append('    { %s, %s, %s },  /* %s */'
                     % (c_string(feature_of[name]), c_string(name), reg,
                        ground))
    lines.append('};')
    lines.append('')
    lines.append('#endif /* %s */' % guard)
    lines.append('')
    with open(out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True, help='QEMU source root')
    ap.add_argument('--isa', required=True, choices=sorted(TARGETS))
    ap.add_argument('--tsv', required=True)
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--namespace', choices=('tcg', 'gdb'), default='tcg',
                    help='which register namespace to join (default tcg)')
    ap.add_argument('--universe', action='store_true',
                    help='print the scraped name universe and exit')
    args = ap.parse_args()

    if args.namespace == 'gdb':
        universe = scrape_gdb(args.root, args.isa)
    else:
        check_no_stray_sites(args.root, args.isa)
        universe = scrape(args.root, args.isa)

    if args.universe:
        for name in sorted(universe):
            print('%s\t%s' % (name, universe[name]))
        return 0

    rows = read_tsv(args.tsv)

    seen = {}
    for name, reg, ground, lineno in rows:
        if name in seen:
            raise SystemExit('%s:%d: %r appears twice (first at line %d)'
                             % (args.tsv, lineno, name, seen[name]))
        seen[name] = lineno

    missing = sorted(set(universe) - set(seen))
    dead = sorted(set(seen) - set(universe))
    if missing or dead:
        msg = ['cst-regmap: %s: the register map and the target disagree.'
               % args.isa]
        for name in missing:
            msg.append('  GAP:  %s is registered at %s and has no row'
                       % (name, universe[name]))
        for name in dead:
            msg.append('  DEAD: %s:%d names %s, which the target never '
                       'registers' % (args.tsv, seen[name], name))
        raise SystemExit('\n'.join(msg))

    if args.namespace == 'gdb':
        emit_gdb(args.isa, rows, universe, args.output)
    else:
        emit(args.isa, rows, args.output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
