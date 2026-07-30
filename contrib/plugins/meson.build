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
    )
  champsim_tracer_cpp_args = ['-std=gnu++17',
                              '-Wno-missing-field-initializers',
                              '-Wno-pedantic']
  if host_os == 'windows'
    champsim_tracer_so = shared_module('champsim_tracer',
                       champsim_tracer_sources + files('win32_linker.c'),
                       include_directories: ['../../include/qemu', '../../include'],
                       cpp_args: champsim_tracer_cpp_args,
                       link_depends: [win32_qemu_plugin_api_lib],
                       link_args: win32_qemu_plugin_api_link_flags,
                       dependencies: [glib, capstone])
  else
    champsim_tracer_so = shared_module('champsim_tracer',
                       champsim_tracer_sources,
                       include_directories: ['../../include/qemu', '../../include'],
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
  isaxcheck_fields = static_library(
    'isaxcheck_fields',
    files('champsim_tracer/tools/isaxcheck_fields.cc',
          'champsim_tracer/champsim_tracer_decode.cc',
          'champsim_tracer/champsim_tracer_mnemonic_tables.cc',
          'champsim_tracer/champsim_tracer_reg_handle_cache.cc'),
    include_directories: ['../../include/qemu', '../../include',
                          'champsim_tracer'],
    cpp_args: champsim_tracer_cpp_args,
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
