# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""The core never depends on the interface (RNF-MAN-01, ADR-0002)."""

import subprocess
import sys


def test_core_imports_neither_gtk_nor_the_interface() -> None:
    """Import every core module in a fresh interpreter and look at what got loaded."""
    code = """
import pkgutil, importlib, sys, berigna.core
for module in pkgutil.walk_packages(berigna.core.__path__, "berigna.core."):
    importlib.import_module(module.name)
forbidden = ("gi.", "berigna.ui")
print(sorted(name for name in sys.modules if name == "gi" or name.startswith(forbidden)))
"""
    result = subprocess.run(  # noqa: S603 - fixed arguments
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]"
