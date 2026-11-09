#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# In the CI only: the Ubuntu containers fetch from Canonical's mirror on Azure, where GitHub's
# runners live, instead of archive.ubuntu.com, which they often fail to reach (2026-11-08: a
# whole job lost to "Unable to connect to archive.ubuntu.com:80"). Same archive, same signed
# Release; nothing changes outside GitHub Actions or on Debian.
#
#   . scripts/espejo-ubuntu.sh   (from the scripts that install packages in a container)
if [ -n "${GITHUB_ACTIONS:-}" ] && [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
  sed -i -e 's|http://archive.ubuntu.com/|http://azure.archive.ubuntu.com/|g' \
    -e 's|http://security.ubuntu.com/|http://azure.archive.ubuntu.com/|g' \
    /etc/apt/sources.list.d/ubuntu.sources
fi
