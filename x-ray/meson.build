if not get_option('tcg').allowed()
   subdir_done()
endif

if get_option('taint_engine')
  tcg_ss = ss.source_set()
  tcg_ss.add(files(
    'x-ray.c',
    'helper.c',
    'callback.c'
  ))

  specific_ss.add_all(when: 'CONFIG_TCG', if_true: tcg_ss)
endif