#!/usr/bin/env python3
#
# The generic word a hand-written decoder's rules carry.
#
# A decodetree target writes its word on the pattern line and
# scripts/decodetree.py emits the statement beside the rule it already
# names.  A hand-written decoder has no pattern line, so the adjudication
# lives in a checked-in TSV and this turns it into macros the decoder's own
# table expands:
#
#     ADD  int.add        ->   #define X86_DF_WORD_ADD  INSN_DF_WORD_INT_ADD
#     UD   -              ->   #define X86_DF_WORD_UD   NULL
#
# WHY MACROS AND NOT A LOOKUP.  The decode table names its rule once, as the
# first argument of an X86_OP_ENTRY row, and the macro pastes the word in
# beside it.  A rule the TSV does not cover then fails to compile, which is
# the completeness guarantee: the build refuses a decoder rule with no
# adjudicated word rather than publishing a silent default for it.
#
# THE CHECK RUNS BOTH WAYS.  --rules names the decoder source; this script
# extracts the rule names from it and requires set equality with the TSV.  A
# rule the decoder gained is a hard error (the word was never adjudicated); a
# row for a rule the decoder no longer has is a hard error too (the
# adjudication outlived its subject, and a table nobody can reach is how a
# stale row survives a rewrite).
#
# The words themselves are validated against include/exec/insn-dataflow-words.h,
# the one file that defines the vocabulary, exactly as decodetree validates
# `!word=`.  A typo is a build error rather than a word arriving at a consumer
# that cannot read it.
#
# Author: Maccoy Merrell
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import os
import re
import sys


def load_vocabulary(path):
    """word -> macro name, from the header that defines the vocabulary."""
    voc = {}
    with open(path) as f:
        for line in f:
            m = re.match(r'#define\s+(INSN_DF_WORD_\w+)\s+"([a-z0-9.]+)"', line)
            if m:
                voc[m.group(2)] = m.group(1)
    if not voc:
        sys.exit('insn-df-words: no words defined in %s' % path)
    return voc


def load_tsv(path, voc):
    """rule -> macro name or None, refusing a word the vocabulary lacks."""
    rows = {}
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip('\n')
            if not line or line.startswith('#'):
                continue
            parts = line.split('\t')
            if len(parts) < 2:
                sys.exit('%s:%d: expected rule<TAB>word' % (path, lineno))
            rule, word = parts[0], parts[1]
            if rule in rows:
                sys.exit('%s:%d: %s stated twice' % (path, lineno, rule))
            if word == '-':
                if len(parts) < 3 or not parts[2].strip():
                    sys.exit('%s:%d: %s states no word and gives no reason; '
                             'a rule with nothing to say says why'
                             % (path, lineno, rule))
                rows[rule] = None
            elif word in voc:
                rows[rule] = voc[word]
            else:
                sys.exit('%s:%d: %s: unknown generic word %r'
                         % (path, lineno, rule, word))
    if not rows:
        sys.exit('insn-df-words: %s has no rows -- a table over nothing is '
                 'not a table' % path)
    return rows


#
# X86_OP_ENTRY* rows name an instruction.  X86_OP_GROUP* rows name a DECODE
# FUNCTION, which then installs the entry the bytes really reached, so a
# group's first argument is not a rule and gets no word here; the nine group
# handlers that patch the entry in place rather than replacing it state their
# rule themselves, beside the gen function they choose.
#
RULE_RE = re.compile(r'X86_OP_ENTRY[0-9rw]*\(\s*([A-Za-z0-9_]+)'
                     r'|X86_OP_ALIAS[0-9rw]*\(\s*([A-Za-z0-9_]+)'
                     r'|X86_DF_ROW\(\s*([A-Za-z0-9_]+)'
                     r'|X86_DF_SET\([^,]+,\s*([A-Za-z0-9_]+)')


def rules_in_source(paths):
    """The rule names the decoder's own table states."""
    names = set()
    for p in paths:
        cont = False
        with open(p) as f:
            for line in f:
                # The macro definitions themselves, and their continuation
                # lines, whose argument is the parameter name and not a rule.
                skip = cont or line.lstrip().startswith('#define')
                cont = skip and line.rstrip('\n').endswith('\\')
                if skip:
                    continue
                for m in RULE_RE.finditer(line):
                    names.add(m.group(1) or m.group(2) or m.group(3) or m.group(4))
    if not names:
        sys.exit('insn-df-words: no rule names found in %s -- the extraction '
                 'found nothing, which is a broken check and not an empty '
                 'decoder' % ', '.join(paths))
    return names


def main():
    ap = argparse.ArgumentParser(
        description="the generic word a hand-written decoder's rules carry")
    ap.add_argument('tsv', help='the adjudication data')
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--vocabulary', required=True,
                    help='include/exec/insn-dataflow-words.h')
    ap.add_argument('--prefix', default='X86_DF_WORD_',
                    help='macro prefix for the generated defines')
    ap.add_argument('--rules', action='append', default=[],
                    help='decoder source to cross-check the rule set against')
    args = ap.parse_args()

    voc = load_vocabulary(args.vocabulary)
    rows = load_tsv(args.tsv, voc)

    if args.rules:
        have = rules_in_source(args.rules)
        missing = sorted(have - set(rows))
        extra = sorted(set(rows) - have)
        if missing:
            sys.exit('insn-df-words: %s: these decode rules have no '
                     'adjudicated word: %s' % (args.tsv, ' '.join(missing)))
        if extra:
            sys.exit('insn-df-words: %s: these rows name no decode rule: %s'
                     % (args.tsv, ' '.join(extra)))

    out = []
    out.append('/*')
    out.append(' * Generated by scripts/insn-df-words.py from')
    out.append(' * %s -- do not edit.' % args.tsv)
    out.append(' *')
    out.append(' * One macro per decode rule, holding the generic word the')
    out.append(' * rule states.  NULL is a statement: the rule has nothing')
    out.append(' * generic to say about itself, and the TSV row says why.')
    out.append(' */')
    for rule in sorted(rows):
        macro = rows[rule]
        out.append('#define %s%-20s %s'
                   % (args.prefix, rule, macro if macro else 'NULL'))
    out.append('')

    text = '\n'.join(out)
    tmp = args.output + '.tmp'
    with open(tmp, 'w') as f:
        f.write(text)
    os.replace(tmp, args.output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
