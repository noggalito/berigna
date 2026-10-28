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
  install: true,
  install_dir: pkgdatadir,
)

install_data(
  application_id + '.gschema.xml',
  install_dir: get_option('datadir') / 'glib-2.0' / 'schemas',
)
# gschemas.compiled in the build tree, for scripts/ejecutar.sh and the tests.
gnome.compile_schemas(build_by_default: true, depend_files: files(application_id + '.gschema.xml'))
