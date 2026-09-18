gen_a64 = [
  decodetree.process('a64.decode', extra_args: ['--static-decode=disas_a64']),
  decodetree.process('sve.decode', extra_args: '--decode=disas_sve'),
  decodetree.process('sme.decode', extra_args: '--decode=disas_sme'),
  decodetree.process('sme-fa64.decode', extra_args: '--static-decode=disas_sme_fa64'),
]

gen_a32 = [
  decodetree.process('neon-shared.decode', extra_args: '--decode=disas_neon_shared'),
  decodetree.process('neon-dp.decode', extra_args: '--decode=disas_neon_dp'),
  decodetree.process('neon-ls.decode', extra_args: '--decode=disas_neon_ls'),
  decodetree.process('vfp.decode', extra_args: '--decode=disas_vfp'),
  decodetree.process('vfp-uncond.decode', extra_args: '--decode=disas_vfp_uncond'),
  decodetree.process('m-nocp.decode', extra_args: '--decode=disas_m_nocp'),
  decodetree.process('mve.decode', extra_args: '--decode=disas_mve'),
  decodetree.process('a32.decode', extra_args: '--static-decode=disas_a32'),
  decodetree.process('a32-uncond.decode', extra_args: '--static-decode=disas_a32_uncond'),
  decodetree.process('t32.decode', extra_args: '--static-decode=disas_t32'),
  decodetree.process('t16.decode', extra_args: ['-w', '16', '--static-decode=disas_t16']),
]

arm_ss.add(gen_a32)
arm_ss.add(when: 'TARGET_AARCH64', if_true: gen_a64)

#
# What arm's helpers do through the pointers they are handed.
#
# insn-df-helper-usage.tsv adjudicates one direction per pointer argument; the
# generator turns the rows into the table target/arm/tcg/insn-df-usage.c
# installs beside the argument shapes the compiler derives from helper.h.
#
# AARCH64 ONLY, AND THE GATE IS THE TABLE'S OWN COMPLETENESS.  helper.h pulls
# in helper-a64.h, helper-sve.h and helper-sme.h behind `#ifdef
# TARGET_AARCH64', so a 32-bit arm target expands a strictly smaller helper
# list -- and insn_dataflow_declare_helper_usage() aborts on a row that names
# no helper this build has, which is the check working.  The table is the
# AArch64 expansion's; 32-bit arm keeps the unbounded record it had.
#
insn_df_usage_arm = custom_target('arm-insn-df-usage.h.inc',
  output: 'insn-df-usage.h.inc',
  input: files('insn-df-helper-usage.tsv'),
  command: [python, files(meson.project_source_root() /
                          'scripts/insn-df-usage.py'),
            '@INPUT@', '-o', '@OUTPUT@'])

arm_ss.add(when: 'TARGET_AARCH64', if_true: [insn_df_usage_arm])

arm_ss.add(files(
  'cpu32.c',
  'gengvec.c',
  'translate.c',
  'translate-m-nocp.c',
  'translate-mve.c',
  'translate-neon.c',
  'translate-vfp.c',
  'crypto_helper.c',
  'hflags.c',
  'iwmmxt_helper.c',
  'm_helper.c',
  'mve_helper.c',
  'neon_helper.c',
  'op_helper.c',
  'tlb_helper.c',
  'vec_helper.c',
  'tlb-insns.c',
  'arith_helper.c',
  'vfp_helper.c',
))

arm_ss.add(when: 'TARGET_AARCH64', if_true: files(
  'insn-df-usage.c',
  'cpu64.c',
  'gengvec64.c',
  'translate-a64.c',
  'translate-sve.c',
  'translate-sme.c',
  'helper-a64.c',
  'mte_helper.c',
  'pauth_helper.c',
  'sme_helper.c',
  'sve_helper.c',
))

arm_system_ss.add(files(
  'psci.c',
))

arm_system_ss.add(when: 'CONFIG_ARM_V7M', if_true: files('cpu-v7m.c'))
arm_user_ss.add(when: 'TARGET_AARCH64', if_false: files('cpu-v7m.c'))
