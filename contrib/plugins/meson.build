contrib_plugins = ['bbv', 'cache', 'cflow', 'drcov', 'execlog', 'hotblocks',
                   'hotpages', 'howvec', 'hwprofile', 'ips', 'stoptrigger']
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
  # ChampSim Tracer: a C++17 plugin, built wherever a C++ compiler exists.
  if host_os != 'windows' and add_languages('cpp', required: false, native: false)
    t += shared_module('champsim_tracer',
                       files('champsim_tracer/plugin.cc',
                             'champsim_tracer/container.cc',
                             'champsim_tracer/wire.cc'),
                       include_directories: '../../include',
                       override_options: ['cpp_std=c++17'],
                       dependencies: glib)
  endif
endif
if t.length() > 0
  alias_target('contrib-plugins', t)
else
  run_target('contrib-plugins', command: find_program('true'))
endif

plugin_modules += t
