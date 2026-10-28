# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""The real application under a display (Xvfb in scripts/verificar.sh and in the CI).

Needs the build tree of Meson (``meson compile -C build/meson``): compiled views and schema.
Settings live in memory, so the tests never touch the user's dconf.
"""

import os
from collections.abc import Callable, Generator, Iterator
from pathlib import Path

import pytest

from berigna.core.i18n import Language
from berigna.core.token.monitor import ReaderState
from support.pki import Pki, build_pki

BUILD = Path(__file__).resolve().parents[2] / "build" / "meson" / "data"
os.environ.setdefault("BERIGNA_RESOURCES", str(BUILD / "berigna.gresource"))
os.environ.setdefault("GSETTINGS_SCHEMA_DIR", str(BUILD))
os.environ["GSETTINGS_BACKEND"] = "memory"

if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
    pytest.skip("needs a display: run under xvfb-run", allow_module_level=True)
if not Path(os.environ["BERIGNA_RESOURCES"]).exists():
    pytest.fail("compile the views first: meson setup build/meson && meson compile -C build/meson")

from gi.repository import Gio, GLib  # noqa: E402

Gio.Resource.load(os.environ["BERIGNA_RESOURCES"])._register()

from berigna.ui import i18n  # noqa: E402
from berigna.ui.application import BerignaApplication  # noqa: E402


class FakeReaders:
    """Stands in for PC/SC; the test changes ``current`` to simulate a card."""

    def __init__(self) -> None:
        self.current: tuple[ReaderState, ...] = ()
        self.closed = False

    def readers(self) -> tuple[ReaderState, ...]:
        return self.current

    def close(self) -> None:
        self.closed = True


Script = Callable[[BerignaApplication], Generator[None, None, None]]


def drive(app: BerignaApplication, script: Script, *, args: list[str] | None = None) -> None:
    """Run ``app`` with its real main loop; ``script`` yields while it waits for something."""
    steps = script(app)
    failure: list[BaseException] = []

    def tick() -> bool:
        try:
            next(steps)
            return GLib.SOURCE_CONTINUE
        except StopIteration:
            pass
        except BaseException as exc:  # reported after the loop ends
            failure.append(exc)
        app.quit()
        return GLib.SOURCE_REMOVE

    def start(*_args: object) -> None:
        GLib.timeout_add(20, tick)

    app.connect("startup", start)
    app.run(["berigna", *(args or [])])
    if failure:
        raise failure[0]


def wait_until(condition: Callable[[], bool], seconds: float = 5) -> Iterator[None]:
    """Yield from a script until ``condition`` holds."""
    for _ in range(int(seconds / 0.02)):
        if condition():
            return
        yield
    raise AssertionError("timed out")


@pytest.fixture
def readers() -> FakeReaders:
    return FakeReaders()


@pytest.fixture(scope="session")
def pki() -> Pki:
    return build_pki()


@pytest.fixture
def app(readers: FakeReaders, pki: Pki) -> Iterator[BerignaApplication]:
    """Offline, with the test PKI as trust store: results do not depend on the network."""
    yield BerignaApplication(
        status_source=lambda: readers, trust_store=lambda: pki.store, online=False, unique=False
    )
    i18n.set_language(Language.ES_PE)
