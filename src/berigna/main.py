# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Entry point of the graphical application (ADR-0002: no public CLI, only files to open).

``BERIGNA_RESOURCES`` points to the compiled views (``berigna.gresource``); the installed
launcher sets it to the package data directory and ``scripts/ejecutar.sh`` to the build tree.
"""

import os
import sys
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    from gi.repository import Gio

    resources = os.environ.get("BERIGNA_RESOURCES")
    if not resources:
        print("berigna: BERIGNA_RESOURCES is not set", file=sys.stderr)
        return 1
    Gio.Resource.load(resources)._register()

    from berigna.core.logs import setup_logging
    from berigna.ui.application import BerignaApplication

    try:
        setup_logging()  # RF-083
    except OSError as exc:  # a read-only home must not stop the program
        print(f"berigna: no technical log: {exc}", file=sys.stderr)

    return int(BerignaApplication().run(list(sys.argv if argv is None else argv)))
