# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Graphical application (ADR-0010). The core keeps pyproject.toml for development and tests.
project(
  'berigna',
  version: '0.1.0.dev0',
  meson_version: '>= 1.7.0',
  license: 'GPL-3.0-or-later',
)

application_id = 'com.noggalito.Berigna'
gnome = import('gnome')
i18n = import('i18n')
python = import('python').find_installation('python3')

pkgdatadir = get_option('prefix') / get_option('datadir') / meson.project_name()
localedir = get_option('prefix') / get_option('localedir')

subdir('data')
subdir('src')
subdir('bin')
subdir('po')

gnome.post_install(glib_compile_schemas: true, gtk_update_icon_cache: true)
