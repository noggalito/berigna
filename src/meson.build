# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# The berigna package with its data files (trust anchors, INDECOPI root). Adding a file needs
# "meson setup --reconfigure", since the list is read when configuring.
package_files = run_command(
  python, '-c',
  'import pathlib; print("\\n".join(sorted(str(p) for p in pathlib.Path("berigna").rglob("*") if p.is_file() and "__pycache__" not in p.parts)))',
  check: true,
).stdout().strip().split('\n')

python.install_sources(package_files, preserve_path: true, pure: true)
