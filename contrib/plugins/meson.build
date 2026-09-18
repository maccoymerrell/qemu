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
      'champsim_tracer/champsim_tracer_isa_properties.cc',
      'champsim_tracer/champsim_tracer_vocabulary.cc',
      'champsim_tracer/champsim_tracer_regmap.cc',
                              'champsim_tracer/champsim_tracer_gdbmap.cc',
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
  foreach r : [['x86_64',  ['target/i386/tcg/translate.c'],
                            ['gdb-xml/i386-64bit.xml']],
               ['aarch64', ['target/arm/tcg/translate.c',
                            'target/arm/tcg/translate-a64.c'],
                            ['gdb-xml/aarch64-core.xml',
                             'gdb-xml/aarch64-fpu.xml']],
               ['riscv64', ['target/riscv/translate.c',
                            'target/riscv/cpu.c'],
                            ['gdb-xml/riscv-64bit-cpu.xml',
                             'gdb-xml/riscv-64bit-fpu.xml']],
               ['mipsel',  ['target/mips/tcg/translate.c',
                            'target/mips/tcg/msa_translate.c',
                            'target/mips/tcg/mxu_translate.c',
                            'target/mips/cpu.c',
                            'target/mips/fpu.c'],
                            ['gdb-xml/mips-cpu.xml']]]
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
    champsim_tracer_gdbmap_deps = []
    foreach g : r[2]
      champsim_tracer_gdbmap_deps += files(meson.project_source_root() / g)
    endforeach
    # The SECOND namespace: the gdbstub spelling, joined from the target's
    # own CORE feature XML.  Same generator, same both-directions refusal;
    # a different registration site because the value-read route goes
    # through qemu_plugin_get_registers(), not through a TCG global.
    champsim_tracer_regmap_gen += custom_target(
      'champsim_tracer_gdbmap_' + r[0] + '.h',
      output: 'champsim_tracer_gdbmap_' + r[0] + '.h',
      input: files('champsim_tracer/regmap/' + r[0] + '.gdb.tsv'),
      depend_files: champsim_tracer_gdbmap_deps,
      command: [python, files(meson.project_source_root() /
                              'scripts/cst-regmap.py'),
                '--root', meson.project_source_root(), '--namespace', 'gdb',
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
  #
  # The repository carries no Capstone at all, so the switch is now only
  # about the capture: the QEMU-side comparison corpora.  The Capstone
  # column of that comparison is written offline by tools/cst_referee.py,
  # through the Python bindings, over the encodings these corpora record.
  champsim_tracer_deps = [glib]
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
                       dependencies: champsim_tracer_deps)
  else
    champsim_tracer_so = shared_module('champsim_tracer',
                       champsim_tracer_sources + champsim_tracer_regmap_gen,
                       include_directories: ['../../include/qemu', '../../include',
                                             '.'],
                       cpp_args: champsim_tracer_cpp_args,
                       dependencies: champsim_tracer_deps)
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
  t += executable(
    'cst_decode',
    files('champsim_tracer/tools/cst_decode_main.cc',
          'champsim_tracer/tools/cst_raw.cc'),
    cpp_args: cst_tools_cpp_args,
    link_with: cst_tools_common,
    install: false)
  # cst_visualize: streams the same shared cst_decode walker and
  # accumulates a chosen metric into instruction-window bins, then
  # writes an SVG.  Its only inputs are the numeric ids in the trace
  # and the trace's own encoding maps.
  t += executable(
    'cst_visualize',
    files('champsim_tracer/tools/cst_visualize.cc'),
    cpp_args: cst_tools_cpp_args,
    link_with: cst_tools_common,
    install: false)
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
