#
# The generic word each decode rule carries.
#
# decode-new.c.inc's table names its rules; insn-df-words.tsv adjudicates one
# word for each; the generator turns the pair into the X86_DF_WORD_<rule>
# macros the table expands, and REFUSES a rule set that does not match the TSV
# in either direction, so the decoder cannot gain a rule with no word.
#
insn_df_words_i386 = custom_target('i386-insn-df-words.h.inc',
  output: 'insn-df-words.h.inc',
  input: files('insn-df-words.tsv'),
  depend_files: files('decode-new.c.inc',
                      meson.project_source_root() /
                      'include/exec/insn-dataflow-words.h'),
  command: [python, files(meson.project_source_root() /
                          'scripts/insn-df-words.py'),
            '@INPUT@', '-o', '@OUTPUT@',
            '--prefix', 'X86_DF_WORD_',
            '--vocabulary', meson.project_source_root() /
                            'include/exec/insn-dataflow-words.h',
            '--rules', meson.project_source_root() /
                       'target/i386/tcg/decode-new.c.inc'])

i386_ss.add(when: 'CONFIG_TCG', if_true: [insn_df_words_i386])

i386_ss.add(when: 'CONFIG_TCG', if_true: files(
  'access.c',
  'bpt_helper.c',
  'cc_helper.c',
  'excp_helper.c',
  'fpu_helper.c',
  'int_helper.c',
  'mem_helper.c',
  'misc_helper.c',
  'mpx_helper.c',
  'seg_helper.c',
  'tcg-cpu.c',
  'translate.c'), if_false: files('tcg-stub.c'))

subdir('system')
subdir('user')
