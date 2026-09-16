#
# Which rule the bytes reached, for a decoder made of switches.
#
# translate.c decodes the base ISA in a nest of hand-written switches, so the
# identity is keyed off each switch's own case labels; insn-df-words.tsv
# adjudicates one generic word per label, and the generator refuses a label
# set and a row set that do not match in either direction.
#
insn_df_ident_mips = custom_target('mips-insn-df-ident.h.inc',
  output: 'insn-df-ident.h.inc',
  input: files('insn-df-words.tsv'),
  depend_files: files('translate.c', 'translate.h',
                      meson.project_source_root() /
                      'include/exec/insn-dataflow-words.h'),
  command: [python, files(meson.project_source_root() /
                          'scripts/mips-df-ident.py'),
            meson.project_source_root() / 'target/mips/tcg/translate.c',
            '@INPUT@', '-o', '@OUTPUT@',
            '--enums', meson.project_source_root() /
                       'target/mips/tcg/translate.h',
            '--vocabulary', meson.project_source_root() /
                            'include/exec/insn-dataflow-words.h'])

gen = [
  insn_df_ident_mips,
  decodetree.process('rel6.decode', extra_args: ['--decode=decode_isa_rel6']),
  decodetree.process('msa.decode', extra_args: '--decode=decode_ase_msa'),
  decodetree.process('tx79.decode', extra_args: '--static-decode=decode_tx79'),
  decodetree.process('vr54xx.decode', extra_args: '--decode=decode_ext_vr54xx'),
  decodetree.process('octeon.decode', extra_args: '--decode=decode_ext_octeon'),
  decodetree.process('lcsr.decode', extra_args: '--decode=decode_ase_lcsr'),
  decodetree.process('godson2.decode', extra_args: ['--static-decode=decode_godson2']),
  decodetree.process('loong-ext.decode', extra_args: ['--static-decode=decode_loong_ext']),
]

mips_ss.add(gen)
mips_ss.add(files(
  'dsp_helper.c',
  'exception.c',
  'fpu_helper.c',
  'ldst_helper.c',
  'lmmi_helper.c',
  'msa_helper.c',
  'msa_translate.c',
  'op_helper.c',
  'rel6_translate.c',
  'translate.c',
  'translate_addr_const.c',
  'txx9_translate.c',
  'vr54xx_helper.c',
  'vr54xx_translate.c',
))
mips_ss.add(when: 'TARGET_MIPS64', if_true: files(
  'tx79_translate.c',
  'octeon_translate.c',
  'lcsr_translate.c',
  'loong_translate.c',
), if_false: files(
  'mxu_translate.c',
))

if have_system
  subdir('system')
endif
