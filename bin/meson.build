# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
configure_file(
  input: 'berigna.in',
  output: 'berigna',
  configuration: {
    'PYTHON': python.full_path(),
    'RESOURCES': pkgdatadir / 'berigna.gresource',
    'LOCALEDIR': localedir,
  },
  install: true,
  install_dir: get_option('bindir'),
  install_mode: 'rwxr-xr-x',
)
