# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
blueprints = custom_target(
  'blueprints',
  input: files('ui/window.blp'),
  output: '.',
  command: [find_program('blueprint-compiler'), 'batch-compile', '@OUTPUT@', '@CURRENT_SOURCE_DIR@', '@INPUT@'],
)

gnome.compile_resources(
  meson.project_name(),
  'berigna.gresource.xml',
  gresource_bundle: true,
  dependencies: blueprints,
  source_dir: meson.current_source_dir(),
  install: true,
  install_dir: pkgdatadir,
)

install_data(
  'icons' / application_id + '.svg',
  install_dir: get_option('datadir') / 'icons' / 'hicolor' / 'scalable' / 'apps',
)
# Small sizes: the reduced symbol, which reads better than the full one (data/brand/README.md).
foreach size : ['16x16', '24x24', '32x32']
  install_data(
    'icons' / application_id + '-small.svg',
    rename: application_id + '.svg',
    install_dir: get_option('datadir') / 'icons' / 'hicolor' / size / 'apps',
  )
endforeach
install_data(
  'icons' / application_id + '-symbolic.svg',
  install_dir: get_option('datadir') / 'icons' / 'hicolor' / 'symbolic' / 'apps',
)

install_data(
  application_id + '.gschema.xml',
  install_dir: get_option('datadir') / 'glib-2.0' / 'schemas',
)
# gschemas.compiled in the build tree, for scripts/ejecutar.sh and the tests.
gnome.compile_schemas(build_by_default: true, depend_files: files(application_id + '.gschema.xml'))
