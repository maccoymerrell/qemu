#!/usr/bin/env python3
#
# The map from a QEMU gdbstub register NAME to the generic register the trace
# publishes.
#
# qemu_plugin_get_registers() hands a plugin a descriptor per register, keyed
# by the (feature, name) pair the target's gdbstub publishes.  Those names are
# the target's own spelling -- "ra" on RISC-V, "x30" on AArch64 -- and the
# wire publishes a generic identifier instead.  Something has to join the two,
# and that something must be complete, because a name with no row is a register
# whose value the trace cannot read at all.
#
# So this generator does not take the name universe on trust.  It reads it out
# of the target's own registration sites -- the gdb feature XML each target
# declares and the C feature builders listed in GDB_TARGETS -- and joins that
# universe against the checked-in adjudication table.  The join
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


# The targets this plugin supports, and the target directory each one's
# sources live in.  check_no_stray_gdb_sites() sweeps that directory for C
# feature builders this generator neither reads nor excludes.
TARGETS = {
    'x86_64': {'dir': 'target/i386'},
    'aarch64': {'dir': 'target/arm'},
    'riscv64': {'dir': 'target/riscv'},
    'mipsel': {'dir': 'target/mips'},
}

# The names QEMU's gdbstub registers.
#
# The value-read route goes through qemu_plugin_get_registers(), whose
# descriptors carry the (feature, name) pair the target's gdbstub publishes.
#
# So the map is read out of the target's own registration site, and for
# the gdbstub that site is the feature XML the target hands gdb: every
# <reg name="..."> inside the <feature name="..."> each listed file declares.
#
# SCOPE, and why it is these files.  The membership of a feature is decided at
# CPU-realize time, but the site that DECLARES the names is a build-time
# artifact, and a row for a feature the running CPU does not register is inert
# rather than wrong: the name is never published by
# qemu_plugin_get_registers(), the handle lookup misses, and the read reports
# no value -- exactly what happens today for a register with no row at all.
#
# A feature is declared in one of TWO shapes, and both are in scope.  Most are
# an XML file this reads directly.  The rest QEMU builds in C, because the
# register WIDTH is a property of the realized CPU rather than of the ISA:
# AArch64 SVE (target/arm/gdbstub64.c) and RISC-V vector
# (target/riscv/gdbstub.c) size their registers from the CPU's vector length.
# Their NAMES are still fixed literals in the builder, so they are joined the
# same way every other register file is -- read out of the target's own
# registration site -- and scrape_gdb_c() refuses any name expression it
# cannot expand rather than guessing at one.
GDB_TARGETS = {
    'x86_64':  {'files': ['gdb-xml/i386-64bit.xml'], 'csites': []},
    'aarch64': {'files': ['gdb-xml/aarch64-core.xml',
                          'gdb-xml/aarch64-fpu.xml'],
                'csites': [('target/arm/gdbstub64.c',
                            'arm_gen_dynamic_svereg_feature')]},
    'riscv64': {'files': ['gdb-xml/riscv-64bit-cpu.xml',
                          'gdb-xml/riscv-64bit-fpu.xml'],
                'csites': [('target/riscv/gdbstub.c',
                            'ricsv_gen_dynamic_vector_feature')]},
    'mipsel':  {'files': ['gdb-xml/mips-cpu.xml'], 'csites': []},
}

# The C-built features this generator deliberately does NOT read, and why.
# The sweep in check_no_stray_gdb_sites() finds every gdb_feature_builder_init
# in the target directory and demands that each one be either scraped above or
# named here, so a target that grows a new dynamic feature breaks the build
# instead of quietly dropping a register file.
GDB_C_EXCLUDED = {
    'arm_gen_dynamic_sysreg_feature':
        'names come from the realized CPU\'s cp_regs hash table, not from '
        'the source: they are not enumerable at build time',
    'arm_gen_dynamic_m_systemreg_feature':
        'AArch32 M-profile; never registered on an AArch64 CPU',
    'arm_gen_dynamic_m_secextreg_feature':
        'AArch32 M-profile; never registered on an AArch64 CPU',
    'riscv_gen_dynamic_csr_feature':
        'names come from csr_ops[] filtered by the realized CPU\'s '
        'predicates, with a printf fallback for unnamed CSRs: they are not '
        'enumerable from the source',
}

FEATURE_RE = re.compile(r'<feature\s+name="([^"]+)"')
XMLREG_RE = re.compile(r'<reg\s+name="([^"]+)"')

BUILDER_INIT_RE = re.compile(r'\bgdb_feature_builder_init\s*\(')
BUILDER_REG_RE = re.compile(r'\bgdb_feature_builder_append_reg\s*\(')


def scrape_gdb(root, isa):
    """{(feature, name) -> where} for every register this target declares.

    Keyed on the PAIR because that is what qemu_plugin_get_registers()
    keys on, and because two features genuinely spell one register the same
    way: AArch64's fpsr and fpcr are declared by aarch64-fpu.xml and again
    by the SVE builder, and the two are mutually exclusive at realize time
    (target/arm/gdbstub.c registers SVE *instead of* the FPU feature).  A
    name-keyed universe could hold only one of them and would emit a row
    whose feature is wrong for half the CPUs.

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
            if (feats[0], n) in universe:
                raise SystemExit('cst-regmap: %s: %s names %r twice'
                                 % (isa, rel, n))
            universe[(feats[0], n)] = rel

    for rel, fn in GDB_TARGETS[isa]['csites']:
        for feature, name in scrape_gdb_c(root, rel, fn):
            if (feature, name) in universe:
                raise SystemExit('cst-regmap: %s: %s names %r twice in %s'
                                 % (isa, fn, name, feature))
            universe[(feature, name)] = '%s:%s' % (rel, fn)
    return universe


def braced_body(text, start):
    """The extent of the {...} block that opens at or after text[start]."""
    i = text.index('{', start)
    depth = 0
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError('unterminated block')


def function_body(text, fn, where):
    """The source span of @fn's body."""
    m = re.search(r'\b%s\s*\(' % re.escape(fn), text)
    if m is None:
        raise SystemExit('cst-regmap: %s: no function named %s' % (where, fn))
    open_paren = text.index('(', m.end() - 1)
    _args, after = split_args(text, open_paren)
    end = braced_body(text, after)
    return text.index('{', after), end


FOR_RE = re.compile(r'\bfor\s*\(')
LOOP_COND_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*<\s*(\d+)\s*$')


def loop_bound_at(text, lo, hi, pos, where):
    """(var, count) of the innermost literal-bounded for-loop around @pos."""
    best = None
    for m in FOR_RE.finditer(text, lo, hi):
        open_paren = text.index('(', m.end() - 1)
        _args, after = split_args(text, open_paren)
        # The three clauses are ';'-separated, not ','-separated.
        clauses = text[open_paren + 1:after - 1].split(';')
        try:
            end = braced_body(text, after)
        except ValueError:
            continue
        if not (m.start() < pos < end):
            continue
        if best is None or m.start() > best[0]:
            best = (m.start(), clauses)
    if best is None:
        raise SystemExit(
            'cst-regmap: %s: a register name is built from a loop variable '
            'with no enclosing for-loop' % where)
    if len(best[1]) != 3:
        raise SystemExit('cst-regmap: %s: for-loop with %d clauses'
                         % (where, len(best[1])))
    cm = LOOP_COND_RE.match(best[1][1])
    if cm is None:
        raise SystemExit(
            'cst-regmap: %s: loop condition %r is not "<var> < <literal>".\n'
            '  A bound this generator cannot evaluate fails generation on\n'
            '  purpose: the alternative is a register file it silently\n'
            '  truncates.' % (where, best[1][1]))
    return cm.group(1), int(cm.group(2))


def expand_printf_name(text, lo, hi, call_pos, expr, where):
    """Names a g_strdup_printf("<fmt>%d", <loopvar>) expression stands for.

    Returns None when @expr is not such a call, so the caller can try the
    next shape; raises when it IS one and cannot be expanded, because a
    format this generator does not understand is a register file it would
    otherwise truncate in silence.
    """
    expr = expr.strip()
    if not expr.startswith('g_strdup_printf'):
        return None
    args, _ = split_args(expr, expr.index('('))
    if len(args) != 2:
        raise SystemExit('cst-regmap: %s: g_strdup_printf with %d arguments'
                         % (where, len(args)))
    fmt = STRING_RE.fullmatch(args[0].strip())
    if fmt is None or fmt.group(1).count('%') != 1 or '%d' not in fmt.group(1):
        raise SystemExit('cst-regmap: %s: register name built by a format '
                         'this generator cannot expand: %r'
                         % (where, args[0].strip()))
    var, count = loop_bound_at(text, lo, hi, call_pos, where)
    if args[1].strip() != var:
        raise SystemExit(
            'cst-regmap: %s: the name is built from %r but the enclosing '
            'loop counts %r' % (where, args[1].strip(), var))
    return [fmt.group(1).replace('%d', str(i)) for i in range(count)]


def scrape_gdb_c(root, rel, fn, text=None):
    """(feature, name) for every register a C feature builder declares.

    The names are literals in the builder -- "ffr", "vg", or the format of a
    literal-bounded loop -- and every other shape is refused, so a target
    that grows a new way of naming a register fails the build rather than
    losing the register.
    """
    where = '%s:%s' % (rel, fn)
    if text is None:
        text = read(os.path.join(root, rel))
    lo, hi = function_body(text, fn, where)

    im = BUILDER_INIT_RE.search(text, lo, hi)
    if im is None:
        raise SystemExit('cst-regmap: %s: builds no gdb feature' % where)
    iargs, _ = split_args(text, text.index('(', im.end() - 1))
    fm = STRING_RE.fullmatch(iargs[2].strip()) if len(iargs) > 2 else None
    if fm is None:
        raise SystemExit('cst-regmap: %s: the feature name is not a string '
                         'literal' % where)
    feature = fm.group(1)

    out = []
    for m in BUILDER_REG_RE.finditer(text, lo, hi):
        open_paren = text.index('(', m.end() - 1)
        args, _ = split_args(text, open_paren)
        line = '%s (line %d)' % (where, text[:m.start()].count('\n') + 1)
        if len(args) < 2:
            raise SystemExit('cst-regmap: %s: append_reg with %d arguments'
                             % (line, len(args)))
        arg = args[1].strip()

        sm = STRING_RE.fullmatch(arg)
        if sm:
            out.append((feature, sm.group(1)))
            continue

        names = expand_printf_name(text, lo, hi, m.start(), arg, line)
        if names is not None:
            out.extend((feature, n) for n in names)
            continue

        # A local assigned from g_strdup_printf() earlier in the body.  The
        # NEAREST preceding assignment is the one that reaches the call: the
        # SVE builder assigns `name` twice, "z%d" for the vector registers
        # and "p%d" for the predicates, and taking the first would publish
        # the z file's names under the predicate registers.
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', arg):
            asg = None
            for am in re.finditer(r'\b%s\s*=\s*g_strdup_printf\s*\('
                                  % re.escape(arg), text[lo:m.start()]):
                asg = lo + am.start()
            if asg is not None:
                rhs = text[text.index('=', asg) + 1:]
                _a, after = split_args(rhs, rhs.index('('))
                names = expand_printf_name(text, lo, hi, m.start(),
                                           rhs[:after], line)
                if names is not None:
                    out.extend((feature, n) for n in names)
                    continue

        raise SystemExit(
            'cst-regmap: %s: unrecognised register-name argument %r.\n'
            '  A new way of naming a register fails generation on purpose:\n'
            '  the alternative is a register the map silently cannot name.'
            % (line, arg))

    if not out:
        raise SystemExit('cst-regmap: %s: declares no registers' % where)
    return out


def check_no_stray_gdb_sites(root, isa):
    """A C-built gdb feature this generator neither reads nor excludes.

    The scraped site list is this generator's own assumption.  Without this
    check a target that grows a dynamic feature would drop a whole register
    file onto the per-ISA fallback with nothing saying so.
    """
    spec = GDB_TARGETS[isa]
    listed = {fn for _rel, fn in spec['csites']}
    stray = []
    for dirpath, _dirs, files in os.walk(
            os.path.join(root, TARGETS[isa]['dir'])):
        for fn in files:
            if not fn.endswith('.c'):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            text = read(path)
            for m in BUILDER_INIT_RE.finditer(text):
                owner = enclosing_function(text, m.start())
                if owner in listed or owner in GDB_C_EXCLUDED:
                    continue
                stray.append('%s:%s' % (rel, owner))
    if stray:
        raise SystemExit(
            'cst-regmap: %s builds gdb features this generator neither reads '
            'nor excludes: %s\n  Add them to GDB_TARGETS[%r][\'csites\'] or '
            'to GDB_C_EXCLUDED with a reason.'
            % (isa, ', '.join(sorted(set(stray))), isa))


FNDEF_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t*]*\b([A-Za-z_][A-Za-z0-9_]*)'
                      r'\s*\([^;]*?\)\s*\{', re.M | re.S)


def enclosing_function(text, pos):
    """The name of the function whose body contains @pos, or '?'."""
    best = '?'
    for m in FNDEF_RE.finditer(text, 0, pos):
        try:
            end = braced_body(text, m.end() - 1)
        except ValueError:
            continue
        if m.start() < pos < end:
            best = m.group(1)
    return best


STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def strip_comments(text):
    """
    Blank out comments, preserving every byte position and newline.

    Positions are preserved because the scrape reports line numbers back to
    the reader, and a reader sent to the wrong line would be worse than no
    line at all.  Comments must go: a source file that explains a
    registration in prose naming the call it looks for would otherwise be
    read as a call, and a scanner that read prose as a call refuses a target
    that is in fact complete.
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
            # A ground may open with a VALUE-READ ADJUDICATION token.  Several
            # gdb names can carry one generic id, and reading the wrong one
            # publishes a different register's bytes under the id's name, so
            # which name the read goes through is a decision and is written
            # down per row rather than inferred.  "route:" is the row a value
            # read resolves through; "noroute:" says this row is not it (and,
            # when every row of an id says it, that the id has no value read
            # at all).  An id with one row needs no token.
            route = None
            for tok, val in (('route:', True), ('noroute:', False)):
                if ground.startswith(tok):
                    route = val
                    ground = ground[len(tok):].strip()
                    break
            if route is not None and not ground:
                raise SystemExit('%s:%d: %s states a route verdict with no '
                                 'ground behind it' % (path, lineno, name))
            rows.append((name, reg, ground, lineno, route))
    return rows


def qualified_key(key):
    """The TSV spelling of a (feature, name) pair.

    A dead row has no feature -- no feature declares it, which is what makes
    it dead -- so it is reported by the name the row actually carries rather
    than under a fabricated qualifier.
    """
    feature, name = key
    return '%s:%s' % (feature, name) if feature else name


def resolve_gdb_keys(path, isa, rows, universe):
    """Bind each TSV row to the (feature, name) pair it names.

    A register spelled by exactly one feature is written plainly: `fpsr`
    when only aarch64-fpu.xml declares it.  A register TWO features spell the
    same way is written `feature:name`, because the two are different
    registers to qemu_plugin_get_registers() even though gdb spells them
    alike, and a plain row could only have named one of them.

    Both directions refuse.  A plain row for an ambiguous name fails, so
    the ambiguity cannot be resolved by whichever feature the scrape
    happened to see first; a qualified row for an unambiguous name fails
    too, so the qualified form cannot spread into rows that do not need it
    and quietly outlive the ambiguity that justified it.
    """
    features_of = {}
    for feature, name in universe:
        features_of.setdefault(name, set()).add(feature)

    out = []
    msg = []
    for name, reg, ground, lineno, route in rows:
        feature, sep, bare = name.rpartition(':')
        if sep and feature in {f for fs in features_of.values() for f in fs}:
            if len(features_of.get(bare, ())) < 2:
                msg.append('  %s:%d: %s is qualified, but %r is declared by '
                           '%d feature(s) -- write it plainly'
                           % (path, lineno, name, bare,
                              len(features_of.get(bare, ()))))
                continue
            out.append((bare, reg, ground, lineno, route, feature))
            continue

        feats = features_of.get(name)
        if feats and len(feats) > 1:
            msg.append('  %s:%d: %r is declared by %d features (%s); write '
                       'one row per feature, spelled "<feature>:%s"'
                       % (path, lineno, name, len(feats),
                          ', '.join(sorted(feats)), name))
            continue
        out.append((name, reg, ground, lineno, route,
                    next(iter(feats)) if feats else None))
    if msg:
        raise SystemExit('\n'.join(
            ['cst-regmap: %s: gdb rows and features disagree.' % isa] + msg))
    return out


def c_string(s):
    return '"%s"' % s.replace('\\', '\\\\').replace('"', '\\"')


def check_route_adjudications(path, isa, rows):
    """Every generic id with more than one gdb name must say which one a
    VALUE READ goes through -- or say, on every one of its rows, that none
    of them does.

    An id with several names is not a spelling choice.  x86's REG_CTRL is
    carried by cr0, cr2, cr3, cr4, cr8 and efer.  Reading the wrong one
    publishes a different register's bytes under the id's name, and reading
    half a container publishes a partial value as a whole one.  Neither is
    something a generator may pick, so the pick is
    a row in the table with a ground behind it, and this refuses the build
    when an ambiguous id has not been adjudicated.

    REG_NONE is exempt: it is the table's own "no generic register" marker
    and never routes a read.
    """
    by_reg = {}
    for row in rows:
        name, reg, _ground, lineno, route = row[0], row[1], row[2], row[3], row[4]
        by_reg.setdefault(reg, []).append((name, lineno, route))

    msg = []
    for reg in sorted(by_reg):
        members = by_reg[reg]
        if reg == 'REG_NONE' or len(members) == 1:
            # A single-row id needs no verdict, but must not contradict
            # itself by writing one that says it is not the route.
            for name, lineno, route in members:
                if route is False:
                    msg.append('  %s:%d: %s is the only row for %s and says '
                               'it is not the value-read route, which leaves '
                               'the id no route at all -- state the ground on '
                               'its own row or drop the token'
                               % (path, lineno, name, reg))
            continue
        routes = [m for m in members if m[2] is True]
        unstated = [m for m in members if m[2] is None]
        if len(routes) == 1 and not unstated:
            continue
        if not routes and not unstated:
            continue            # every row says noroute: the id has none
        msg.append('  %s: %s is carried by %d names (%s) and is not '
                   'adjudicated: %d row(s) claim the value-read route and '
                   '%d state no verdict'
                   % (path, reg, len(members),
                      ', '.join(m[0] for m in members),
                      len(routes), len(unstated)))
        for name, lineno, route in members:
            if route is None:
                msg.append('    %s:%d: %s states no route verdict'
                           % (path, lineno, name))
    if msg:
        raise SystemExit('\n'.join(
            ['cst-regmap: %s: ambiguous value-read routes.' % isa] + msg))


def emit_gdb(isa, rows, out):
    guard = 'CHAMPSIM_TRACER_GDBMAP_%s_H' % isa.upper()
    lines = []
    lines.append('/*')
    lines.append(' * GENERATED by scripts/cst-regmap.py --namespace gdb from')
    lines.append(' * contrib/plugins/champsim_tracer/regmap/%s.gdb.tsv.' % isa)
    lines.append(' * DO NOT EDIT: change the TSV or the generator.')
    lines.append(' *')
    lines.append(' * The gdbstub spelling of this target\'s register')
    lines.append(' * features, joined to the wire\'s generic ids.  This is the')
    lines.append(' * namespace qemu_plugin_get_registers() hands a plugin, so')
    lines.append(' * it is the namespace a VALUE READ resolves through.')
    lines.append(' */')
    lines.append('#ifndef %s' % guard)
    lines.append('#define %s' % guard)
    lines.append('')
    lines.append('static const CstGdbMapRow cst_gdbmap_%s[] = {' % isa)
    # An id named by exactly one row routes through it without needing a
    # verdict; check_route_adjudications() has already refused anything else.
    n_rows_for = {}
    for row in rows:
        n_rows_for[row[1]] = n_rows_for.get(row[1], 0) + 1
    for name, reg, ground, _lineno, route, feature in sorted(
            rows, key=lambda r: (r[0], r[5] or '')):
        is_route = (route is True or
                    (route is None and reg != 'REG_NONE' and
                     n_rows_for[reg] == 1))
        lines.append('    { %s, %s, %s, %s },  /* %s */'
                     % (c_string(feature), c_string(name), reg,
                        'true' if is_route else 'false', ground))
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
    ap.add_argument('--namespace', choices=('gdb',), default='gdb',
                    help='which register namespace to join (only gdb)')
    ap.add_argument('--universe', action='store_true',
                    help='print the scraped name universe and exit')
    args = ap.parse_args()

    check_no_stray_gdb_sites(args.root, args.isa)
    universe = scrape_gdb(args.root, args.isa)

    if args.universe:
        for key in sorted(universe):
            print('%s\t%s' % (qualified_key(key), universe[key]))
        return 0

    rows = read_tsv(args.tsv)

    rows = resolve_gdb_keys(args.tsv, args.isa, rows, universe)

    seen = {}
    for row in rows:
        name, lineno = row[0], row[3]
        key = (row[5], name)
        if key in seen:
            raise SystemExit('%s:%d: %r appears twice (first at line %d)'
                             % (args.tsv, lineno, name, seen[key]))
        seen[key] = lineno

    missing = sorted(set(universe) - set(seen))
    dead = sorted(set(seen) - set(universe))
    if missing or dead:
        spell = qualified_key
        msg = ['cst-regmap: %s: the register map and the target disagree.'
               % args.isa]
        for key in missing:
            msg.append('  GAP:  %s is registered at %s and has no row'
                       % (spell(key), universe[key]))
        for key in dead:
            msg.append('  DEAD: %s:%d names %s, which the target never '
                       'registers' % (args.tsv, seen[key], spell(key)))
        raise SystemExit('\n'.join(msg))

    check_route_adjudications(args.tsv, args.isa, rows)
    emit_gdb(args.isa, rows, args.output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
