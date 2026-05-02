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
      'champsim_tracer.cc',
      'champsim_tracer_decode.cc',
      'champsim_tracer_wp.cc',
      'champsim_tracer_output.cc',
      'champsim_tracer_writer.cc',
      'champsim_tracer_branch_history.cc',
      'champsim_tracer_bb_template_cache.cc',
      'champsim_tracer_reg_handle_cache.cc',
      'champsim_tracer_simpoint_manager.cc',
      'champsim_tracer_mnemonic_tables.c',
    )
  champsim_tracer_cpp_args = ['-std=gnu++17',
                              '-Wno-missing-field-initializers',
                              '-Wno-pedantic']
  if host_os == 'windows'
    t += shared_module('champsim_tracer',
                       champsim_tracer_sources + files('win32_linker.c'),
                       include_directories: '../../include/qemu',
                       cpp_args: champsim_tracer_cpp_args,
                       link_depends: [win32_qemu_plugin_api_lib],
                       link_args: win32_qemu_plugin_api_link_flags,
                       dependencies: [glib, capstone])
  else
    t += shared_module('champsim_tracer',
                       champsim_tracer_sources,
                       include_directories: '../../include/qemu',
                       cpp_args: champsim_tracer_cpp_args,
                       dependencies: [glib, capstone])
  endif
  endif
endif
if t.length() > 0
  alias_target('contrib-plugins', t)
else
  run_target('contrib-plugins', command: find_program('true'))
endif

plugin_modules += t
