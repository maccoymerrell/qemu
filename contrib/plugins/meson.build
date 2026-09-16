contrib_plugins = ['bbv', 'cache', 'cflow', 'drcov', 'execlog', 'hotblocks',
                   'hotpages', 'howvec', 'hwprofile', 'ips',
                   'stoptrigger']
if host_os != 'windows'
  # lockstep uses socket.h
  contrib_plugins += 'lockstep'
endif

t = []
if get_option('plugins')
  foreach i : contrib_plugins
    if host_os == 'windows'
      t += shared_module(i, files(i + '.c') + 'win32_linker.c',
                        include_directories: '../../include/qemu',
                        link_depends: [win32_qemu_plugin_api_lib],
                        link_args: win32_qemu_plugin_api_link_flags,
                        dependencies: glib)
    else
      t += shared_module(i, files(i + '.c'),
                        include_directories: '../../include/qemu',
                        dependencies: glib)
    endif
  endforeach

  # champsim_tracer is a C++ plugin split across multiple TUs.
  # Enable C++ for this subdir (may not already be enabled project-wide).
  has_cpp = add_languages('cpp', required: false, native: false)
  if has_cpp
    champsim_tracer_sources = files(
      'champsim_tracer/champsim_tracer.cc',
      'champsim_tracer/champsim_tracer_decode.cc',
      'champsim_tracer/champsim_tracer_wp.cc',
      'champsim_tracer/champsim_tracer_delay.cc',
      'champsim_tracer/champsim_tracer_output.cc',
      'champsim_tracer/champsim_tracer_writer.cc',
      'champsim_tracer/champsim_tracer_branch_history.cc',
      'champsim_tracer/champsim_tracer_bb_template_cache.cc',
      'champsim_tracer/champsim_tracer_reg_handle_cache.cc',
      'champsim_tracer/champsim_tracer_simpoint_manager.cc',
      'champsim_tracer/champsim_tracer_stats.cc',
      'champsim_tracer/champsim_tracer_stats_report.cc',
      'champsim_tracer/champsim_tracer_marker_detect.cc',
      'champsim_tracer/champsim_tracer_scoreboard.cc',
      'champsim_tracer/champsim_tracer_trace_segment_manager.cc',
      'champsim_tracer/champsim_tracer_tar.cc',
      'champsim_tracer/champsim_tracer_reg_snap_collector.cc',
      'champsim_tracer/champsim_tracer_bb_chain_assembler.cc',
      'champsim_tracer/champsim_tracer_mem_access_recorder.cc',
      'champsim_tracer/champsim_tracer_path_builder.cc',
      'champsim_tracer/champsim_tracer_wp_thread_state.cc',
      'champsim_tracer/champsim_tracer_plugin_config.cc',
      'champsim_tracer/champsim_tracer_mnemonic_tables.cc',
      'champsim_tracer/champsim_tracer_vocabulary.cc',
      'champsim_tracer/champsim_tracer_regmap.cc',
      'champsim_tracer/champsim_tracer_qdep.cc',
      'champsim_tracer/champsim_tracer_capture.cc',
    )

  # The register map: one generated table per ISA, joining the names QEMU
  # registers its registers under to the generic ids the wire publishes.
  #
  # Generated rather than written because the name universe belongs to the
  # TARGET -- it is whatever strings reach tcg_global_mem_new() and
  # insn_dataflow_declare_regfile() -- and the generator reads that universe
  # out of the target's own sources and refuses in BOTH directions: a
  # registered name with no adjudicated row, or a row naming nothing the
  # target registers, fails generation and therefore the build.  The
  # depend_files list is what makes that refusal timely: a target that adds a
  # register re-runs the join instead of shipping a map that is one register
  # short.
  champsim_tracer_regmap_gen = []
  foreach r : [['x86_64',  ['target/i386/tcg/translate.c']],
               ['aarch64', ['target/arm/tcg/translate.c',
                            'target/arm/tcg/translate-a64.c']],
               ['riscv64', ['target/riscv/translate.c',
                            'target/riscv/cpu.c']],
               ['mipsel',  ['target/mips/tcg/translate.c',
                            'target/mips/tcg/msa_translate.c',
                            'target/mips/tcg/mxu_translate.c',
                            'target/mips/cpu.c',
                            'target/mips/fpu.c']]]
    champsim_tracer_regmap_deps = []
    foreach f : r[1]
      champsim_tracer_regmap_deps += files(meson.project_source_root() / f)
    endforeach
    champsim_tracer_regmap_gen += custom_target(
      'champsim_tracer_regmap_' + r[0] + '.h',
      output: 'champsim_tracer_regmap_' + r[0] + '.h',
      input: files('champsim_tracer/regmap/' + r[0] + '.tsv'),
      depend_files: champsim_tracer_regmap_deps,
      command: [python, files(meson.project_source_root() /
                              'scripts/cst-regmap.py'),
                '--root', meson.project_source_root(),
                '--isa', r[0], '--tsv', '@INPUT@', '-o', '@OUTPUT@'])
  endforeach
  champsim_tracer_cpp_args_base = ['-std=gnu++17',
                                   '-Wno-missing-field-initializers',
                                   '-Wno-pedantic']
  champsim_tracer_cpp_args = champsim_tracer_cpp_args_base
  # The comparison capture is apparatus and does not ship.  Without this the
  # capture TU compiles to nothing and the object carries neither its code nor
  # the names of the variables that would drive it -- a property nm and strings
  # can check, which is why it is a build option and not a runtime one.
  if get_option('cst_capture')
    champsim_tracer_cpp_args += ['-DCST_CAPTURE']
  endif
  if host_os == 'windows'
    champsim_tracer_so = shared_module('champsim_tracer',
                       champsim_tracer_sources + champsim_tracer_regmap_gen +
                       files('win32_linker.c'),
                       include_directories: ['../../include/qemu', '../../include',
                                             '.'],
                       cpp_args: champsim_tracer_cpp_args,
                       link_depends: [win32_qemu_plugin_api_lib],
                       link_args: win32_qemu_plugin_api_link_flags,
                       dependencies: [glib, capstone])
  else
    champsim_tracer_so = shared_module('champsim_tracer',
                       champsim_tracer_sources + champsim_tracer_regmap_gen,
                       include_directories: ['../../include/qemu', '../../include',
                                             '.'],
                       cpp_args: champsim_tracer_cpp_args,
                       dependencies: [glib, capstone])
  endif
  t += champsim_tracer_so

  # Static-TLS budget tripwire: fail the BUILD if the plugin's PT_TLS memsz
  # grows past the ceiling, instead of failing system-mode dlopen at RUNTIME
  # with glibc's "cannot allocate memory in static TLS block" (an error that
  # names neither the plugin nor the offending thread_local).  The ceiling is
  # a tripwire against growth, not a model of glibc: the real budget is
  # glibc-version- and binary-dependent (surplus 1664 bytes observed on the
  # reference host); 1280 = the current PT_TLS memsz (0x4f8 = 1272) + 8 bytes
  # of slack, so any new TLS variable trips it at build time.  Raise it only
  # together with a re-measured system-mode load test.  ELF/glibc concern, so
  # skipped on Windows; readelf is required (a check that cannot find its
  # subject must fail, not skip) -- llvm-readelf is an accepted stand-in.
  if host_os != 'windows'
    readelf = find_program('readelf', 'llvm-readelf')
    t += custom_target('champsim-tracer-tls-guard',
                       input: champsim_tracer_so,
                       output: 'champsim_tracer_tls_guard.ok',
                       command: [files('champsim_tracer/check_static_tls.sh'),
                                 readelf, '@INPUT@', '@OUTPUT@', '1280'],
                       build_by_default: true)
  endif

  # Offline trace tools.  cst_decode and cst_audit consume .cst files
  # produced by the plugin; they share a small static library that
  # parses the wire format (header / templates / body delta replay).
  # No QEMU / glib dependency: the tools are self-contained C++17
  # binaries built alongside the plugin so users get them in the same
  # build directory.
  cst_tools_common_sources = files(
    'champsim_tracer/tools/cst_format.cc',
    'champsim_tracer/tools/cst_decode.cc',
  )
  cst_tools_cpp_args = ['-std=gnu++17',
                        '-Wno-missing-field-initializers']
  cst_tools_common = static_library(
    'cst_tools_common',
    cst_tools_common_sources,
    cpp_args: cst_tools_cpp_args,
    install: false)
  t += executable(
    'cst_audit',
    files('champsim_tracer/tools/cst_audit_main.cc'),
    cpp_args: cst_tools_cpp_args,
    link_with: cst_tools_common,
    install: false)
  # cst_decode uses Capstone for the --objdump-style disasm column.
  # Pin to QEMU's bundled subprojects/capstone (built from
  # capstone.wrap) rather than the project-default capstone variable
  # which can resolve to a system pkg-config copy whose layout differs.
  # Sticking with the subproject keeps cst_decode reproducible across
  # hosts and matches the same Capstone build the plugin links against.
  #
  # The capstone integration lives in cst_objdump.cc; CST_HAVE_CAPSTONE
  # toggles between the real backend (this build) and a no-op stub
  # (used by downstream consumers who lift the decoder into their own
  # tooling without a capstone dependency).
  cst_capstone_dep = subproject('capstone', required: true) \
                         .get_variable('capstone_dep')
  t += executable(
    'cst_decode',
    files('champsim_tracer/tools/cst_decode_main.cc',
          'champsim_tracer/tools/cst_raw.cc',
          'champsim_tracer/tools/cst_objdump.cc'),
    cpp_args: cst_tools_cpp_args + ['-DCST_HAVE_CAPSTONE=1'],
    link_with: cst_tools_common,
    dependencies: [cst_capstone_dep],
    install: false)
  # cst_visualize: streams the same shared cst_decode walker and
  # accumulates a chosen metric into instruction-window bins, then
  # writes an SVG.  No Capstone dependency — its only inputs are the
  # numeric ids in the trace and the trace's own encoding maps.
  t += executable(
    'cst_visualize',
    files('champsim_tracer/tools/cst_visualize.cc'),
    cpp_args: cst_tools_cpp_args,
    link_with: cst_tools_common,
    install: false)
  # capstone_workaround_probe: retest harness for the Capstone-defect
  # workarounds catalogued in disas/capstone.c -- see that file and
  # docs/troubleshooting.rst ("Retiring a Capstone workaround") for the
  # full retirement procedure this tool automates. Pins to the same
  # subprojects/capstone build as cst_decode, for the same reason.
  t += executable(
    'capstone_workaround_probe',
    files('champsim_tracer/tools/capstone_workaround_probe.cc'),
    cpp_args: cst_tools_cpp_args,
    dependencies: [cst_capstone_dep],
    install: false)
  # isaxcheck: static cross-check of the decode metadata the tracer actually
  # consumes against a second, independently maintained decoder (the LLVM MC
  # layer).  The Capstone side is cap_disas_raw_detail() from
  # disas/capstone.c -- the exact boundary the plugin calls, workarounds
  # included -- so a working workaround shows up as the *absence* of a
  # disagreement.  That is why disas/capstone.c is compiled in here rather
  # than the tool re-deriving Capstone detail on its own: re-deriving would
  # duplicate the code under test.  The extra include directory is the
  # project root, which resolves both the in-tree headers disas/capstone.c
  # needs and the generated config-host.h in the build tree.
  #
  # LLVM is an optional host dependency (llvm-18-dev or newer supplying
  # llvm-config).  Without it the target is skipped and the validator's
  # gating check reports the gate as unavailable rather than silently
  # passing -- see validator _full.py, check "features.isa_crosscheck".
  llvm_config = find_program('llvm-config-18', 'llvm-config-19',
                             'llvm-config-20', 'llvm-config',
                             required: false)
  # isaxcheck_fields: the tracer's own dependency model, linked into
  # isaxcheck so the gate can compare the InsnFields the trace is actually
  # built from and not only the decode boundary those fields derive from.
  # The plugin repairs some Capstone defects INSIDE
  # decode_detail_to_generic() -- apply_isa_branch_fixups() restores the
  # RISC-V link-register dataflow the aliased jal/jalr/ret forms hide --
  # and a gate that stops at the boundary cannot tell a working repair from
  # a regressed one, because the defect a regression would reintroduce is
  # already in the gate's expected output.
  #
  # A separate static library rather than more sources on the isaxcheck
  # target, for one concrete reason: the plugin's headers are reached as
  # "qemu-plugin.h" and need ../../include/qemu on the include path, which
  # is exactly the directory isaxcheck must NOT have (include/qemu/ctype.h
  # shadows <cctype> for any TU that reaches for it).  Per-target include
  # directories keep the two include worlds apart.
  # champsim_tracer_decode.cc is compiled in here verbatim: there is no
  # second copy of the dependency model, because a gate measuring a
  # reimplementation would measure the wrong thing.
  #
  # Built WITHOUT -DCST_CAPTURE even when the plugin has it: the capture reads
  # QEMU's dataflow statement ABI, which only an emulator provides, and this
  # library links against neither.  The gate's subject is the dependency model,
  # not the apparatus that scores it, so the capture compiling to nothing here
  # removes a link dependency without removing anything the gate measures.
  isaxcheck_fields = static_library(
    'isaxcheck_fields',
    files('champsim_tracer/tools/isaxcheck_fields.cc',
          'champsim_tracer/champsim_tracer_decode.cc',
          'champsim_tracer/champsim_tracer_capture.cc',
          'champsim_tracer/champsim_tracer_mnemonic_tables.cc',
          'champsim_tracer/champsim_tracer_reg_handle_cache.cc'),
    include_directories: ['../../include/qemu', '../../include',
                          'champsim_tracer'],
    cpp_args: champsim_tracer_cpp_args_base,
    dependencies: [glib, cst_capstone_dep],
    install: false)
  # cst_referee: the EXTERNAL referee -- the Capstone side of the tracer's
  # two-decoder comparison, produced offline from the encodings a QEMU-side
  # corpus already records.
  #
  # Checking Capstone belongs outside QEMU.  While both columns were written
  # from inside one running emulator, the comparison was a dependent of its
  # own subject: the moment the wire stopped consulting the Capstone operand
  # walk, the walk stopped being called and every Capstone row stopped being
  # written, leaving the whole-population loss bar with no subject rather than
  # a number.  This binary links no plugin .so and no emulator, so nothing
  # done to the tracer's Capstone dependency can make it stop answering.
  #
  # It shares isaxcheck's two-include-world arrangement for the same reason:
  # the plugin's headers need ../../include/qemu, which is exactly the
  # directory a TU reaching for <cctype> must not have.  The library half sees
  # the plugin world; the driver sees disas/capstone.c's.
  #
  # Built WITH -DCST_CAPTURE, unlike isaxcheck_fields: the corpora this writes
  # must be the ones champsim_tracer_capture.cc writes, from the same code, or
  # the referee would be scoring against a second implementation of the
  # format.  The QEMU-side statement entry points that capture also declares
  # are stubbed in cst_referee_fields.cc and every stub ABORTS -- see the note
  # there for why a stub that answered would be the silent-false-success shape.
  #
  # Pinned to subprojects/capstone, and the wrap's own revision string is
  # compiled in so a wrap bump re-stamps every corpus the tool writes.  A
  # comparison run against a different Capstone would turn version differences
  # into decoder disagreements, so version parity is part of the bar and the
  # tool refuses at startup if the library it loaded is not the one its
  # headers describe.
  cst_capstone_pin = 'unstamped'
  foreach l : fs.read(meson.project_source_root() /
                      'subprojects/capstone.wrap').strip().split('\n')
    if l.strip().startswith('revision')
      cst_capstone_pin = l.split('=')[1].strip()
    endif
  endforeach
  cst_referee_fields = static_library(
    'cst_referee_fields',
    files('champsim_tracer/tools/cst_referee_fields.cc',
          'champsim_tracer/champsim_tracer_decode.cc',
          'champsim_tracer/champsim_tracer_capture.cc',
          'champsim_tracer/champsim_tracer_mnemonic_tables.cc',
          'champsim_tracer/champsim_tracer_reg_handle_cache.cc',
          'champsim_tracer/champsim_tracer_vocabulary.cc',
          'champsim_tracer/champsim_tracer_regmap.cc') +
    champsim_tracer_regmap_gen,
    include_directories: ['../../include/qemu', '../../include',
                          'champsim_tracer'],
    cpp_args: champsim_tracer_cpp_args_base + ['-DCST_CAPTURE'],
    dependencies: [glib, cst_capstone_dep],
    install: false)
  t += executable(
    'cst_referee',
    files('champsim_tracer/tools/cst_referee.cc') +
    files('../../disas/capstone.c'),
    cpp_args: cst_tools_cpp_args +
              ['-DCST_REFEREE_CAPSTONE_PIN="' + cst_capstone_pin + '"'],
    c_args: ['-std=gnu11'],
    # NOTE: deliberately NOT ../../include/qemu; see isaxcheck below.
    include_directories: ['../../include', '../..',
                          'champsim_tracer/tools'],
    link_with: cst_referee_fields,
    dependencies: [glib, cst_capstone_dep],
    install: false)
  if llvm_config.found()
    llvm_cxxflags = []
    foreach f : run_command(llvm_config, '--cxxflags',
                            check: true).stdout().strip().split()
      # Drop the C++ standard llvm-config asks for; cst_tools_cpp_args pins
      # gnu++17 and a duplicate -std= is a hard error on some compilers.
      if not f.startswith('-std=')
        llvm_cxxflags += f
      endif
    endforeach
    llvm_ldflags = run_command(llvm_config, '--link-shared', '--ldflags',
                               check: true).stdout().strip().split()
    llvm_libs = run_command(llvm_config, '--link-shared', '--libs',
                            check: true).stdout().strip().split()
    t += executable(
      'isaxcheck',
      files('champsim_tracer/tools/isaxcheck.cc') + files('../../disas/capstone.c'),
      cpp_args: cst_tools_cpp_args + llvm_cxxflags,
      c_args: ['-std=gnu11'],
      link_args: llvm_ldflags + llvm_libs,
      # NOTE: deliberately NOT ../../include/qemu -- that directory holds
      # include/qemu/ctype.h, which shadows the C++ standard library's
      # <cctype> for any TU that reaches for it.  Everything this tool needs
      # is spelled "qemu/..." and resolves through ../../include.
      include_directories: ['../../include', '../..'],
      link_with: isaxcheck_fields,
      dependencies: [glib, cst_capstone_dep],
      install: false)
  else
    warning('llvm-config not found: skipping the isaxcheck decoder ' +
            'cross-check gate (install llvm-18-dev or newer)')
  endif
  # cst_attach: ptrace launcher that injects the trace marker at a target's
  # entry so the plugin attaches + pins to its address space (system mode).
  # Plain C, no deps.  It runs INSIDE the guest, so this host build only
  # serves a guest of the host's architecture; for any other guest,
  # cross-build the same source statically against that guest's toolchain
  # (backends: x86/x86-64, aarch64, rv64, little-endian mips32 — see the
  # file header).  The validator does this for you under --system --attach.
  t += executable(
    'cst_attach',
    files('champsim_tracer/tools/cst_attach.c'),
    c_args: ['-std=gnu11'],
    install: false)
  endif
endif
if t.length() > 0
  alias_target('contrib-plugins', t)
else
  run_target('contrib-plugins', command: find_program('true'))
endif

plugin_modules += t
