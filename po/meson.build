# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Installs the catalogues of po/LINGUAS. The template and the merge are done by
# scripts/traducciones.sh, which also handles the views (.blp).
i18n.gettext(meson.project_name(), preset: 'glib')

# Any Southern Quechua setting finds the catalogue (ADR-0015).
foreach alias : ['quy', 'qu']
  install_symlink(
    meson.project_name() + '.mo',
    pointing_to: localedir / 'quz' / 'LC_MESSAGES' / meson.project_name() + '.mo',
    install_dir: localedir / alias / 'LC_MESSAGES',
  )
endforeach
