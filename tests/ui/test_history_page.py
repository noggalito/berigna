# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""History of operations (RF-082) and the trusted certificates in Preferences (RF-060)."""

import csv
import datetime as dt
import io
from collections.abc import Generator
from pathlib import Path

from berigna.core.history import Entry, Kind
from berigna.ui.application import BerignaApplication
from berigna.ui.history import entry_subtitle
from berigna.ui.presentation import trust_store_view
from conftest import drive, wait_until
from support.pki import Pki, minimal_pdf


def _sign(app: BerignaApplication, path: Path) -> Generator[None, None, None]:
    assert app.main_window is not None
    yield from wait_until(lambda: app.main_window is not None and app.main_window.signing)
    page = app.main_window.signing
    assert page is not None
    page._sign.emit("clicked")
    yield from wait_until(lambda: page.pin_dialog is not None, 10)
    assert page.pin_dialog is not None
    page.pin_dialog.entry.set_text("123456")
    page.pin_dialog.sign_button.emit("clicked")
    yield from wait_until(lambda: page.result is not None, 10)


def test_signing_and_verifying_are_recorded(app: BerignaApplication, tmp_path: Path) -> None:
    path = tmp_path / "contrato.pdf"
    path.write_bytes(minimal_pdf())
    exported = tmp_path / "historial.csv"

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from _sign(app, path)
        window = app.main_window
        assert window is not None
        assert window.signing is not None
        window.signing._verify_result()  # open the signed copy: verified and recorded
        yield from wait_until(
            lambda: window.verification is not None and window.verification.verification
        )
        app.activate_action("history", None)
        yield from wait_until(lambda: window.history is not None)
        page = window.history
        assert page is not None
        stack = window._navigation.get_navigation_stack()
        depth = stack.get_n_items()
        app.activate_action("history", None)  # again from the menu: no second copy
        assert window.history is page
        assert stack.get_n_items() == depth
        kinds = [entry.kind for entry in page.entries]
        assert kinds == [Kind.VERIFY, Kind.SIGN]
        verified, signed = page.entries
        assert (signed.file_name, signed.result, signed.level) == ("contrato.pdf", "ok", "B-B")
        assert signed.detail == "revocation-unchecked"  # offline in the tests (RF-006)
        assert signed.signed_name == "contrato-firmado.pdf"
        assert signed.signer == "QUISPE MAMANI ROSA FIR ****4321 hard"
        assert verified.file_name == "contrato-firmado.pdf"
        assert verified.signed_sha256 is None
        assert verified.file_sha256 == signed.signed_sha256  # the row matches the file
        page.search.set_text("contrato-firmado")
        page.refresh()
        assert len(page.entries) == 2
        page.search.set_text("no-existe")
        page.refresh()
        assert page.entries == []
        assert page._stack.get_visible_child_name() == "empty"
        page.search.set_text("")
        page.refresh()
        page.export(exported)
        page.clear()
        assert page.entries == []
        assert not page._clear.get_sensitive()

    drive(app, script, args=[str(path)])
    rows = list(csv.reader(io.StringIO(exported.read_text(encoding="utf-8"))))
    assert [row[1] for row in rows[1:]] == ["Verificación", "Firma"]


def test_switched_off(app: BerignaApplication, tmp_path: Path) -> None:
    path = tmp_path / "contrato.pdf"
    path.write_bytes(minimal_pdf())

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        assert app.settings is not None
        app.settings.set_boolean("history-enabled", False)
        try:
            yield from _sign(app, path)
            app.activate_action("history", None)
            window = app.main_window
            assert window is not None
            yield from wait_until(lambda: window.history is not None)
            assert window.history is not None
            assert window.history.empty.get_title() == "El historial está desactivado"
        finally:
            app.settings.reset("history-enabled")

    drive(app, script, args=[str(path)])


def test_subtitles() -> None:
    moment = dt.datetime(2026, 10, 29, 5, 3, tzinfo=dt.UTC)
    signed = Entry(moment, Kind.SIGN, "a.pdf", "aa", "ok", "a-firmado.pdf", "bb", "B-B")
    assert entry_subtitle(signed).endswith(" · Firmado (B-B) como a-firmado.pdf")
    failed = Entry(moment, Kind.BATCH, "a.pdf", "aa", "error", detail="ERR-301")
    assert " · No firmado: El archivo cambió" in entry_subtitle(failed)
    verified = Entry(moment, Kind.VERIFY, "a.pdf", "aa", "TOTAL-PASSED", detail="1/2")
    assert entry_subtitle(verified).endswith(" · Verificado: 1 de 2 firmas válidas")
    assert entry_subtitle(signed).startswith("2026-10-29 a las ")
    unchecked = Entry(
        moment,
        Kind.SIGN,
        "a.pdf",
        "aa",
        "ok",
        "a-firmado.pdf",
        "bb",
        "B-B",
        detail="revocation-unchecked",
    )
    assert entry_subtitle(unchecked).endswith(" · revocación no comprobada")


def test_trusted_certificates(pki: Pki, tmp_path: Path) -> None:
    from berigna.core.trust import TrustStore

    store = TrustStore.load_bundled()
    user = tmp_path / "anclas"
    user.mkdir()
    from cryptography.hazmat.primitives import serialization

    (user / "ca.pem").write_bytes(pki.root.public_bytes(serialization.Encoding.PEM))
    groups = dict(trust_store_view(store.with_user_anchors(user)))
    assert list(groups) == ["Incluidos en berigna", "Añadidos por ti"]
    bundled = groups["Incluidos en berigna"]
    assert len(bundled) == 7
    names = [name for name, _details in bundled]
    assert names.count("ECEP-RENIEC CA Class 3") == 2
    root_3 = dict(bundled)["ECERNEP PERU CA ROOT 3"]
    assert root_3.startswith("Raíz · vigente hasta el 2042-08-1")
    assert root_3.endswith(
        "SHA-256 9650 8217 C36F 3BBC 556E 2E07 D7AB 50C4 0DA8 027C 3882 3581 3322 E41B 87A5 68BE"
    )


def test_a_listed_intermediate_is_shown_as_what_it_is(pki: Pki) -> None:
    """ADR-0022: an intermediate listed in the TSL is an anchor, but it is still an
    intermediate certificate, and Preferences says so."""
    from berigna.core.trust import TrustedCertificate, TrustStore

    store = TrustStore([TrustedCertificate(pki.ca, "root", "TSL")])
    [(title, [(name, details)])] = trust_store_view(store)
    assert title == "De la lista de confianza de INDECOPI"
    assert name == "TEST ECEP CA Class 2"
    assert details.startswith("Intermedio · vigente hasta el ")


def test_preferences_show_history_and_store(app: BerignaApplication) -> None:
    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.main_window is not None)
        app.show_preferences()
        dialog = app.preferences
        assert dialog is not None
        assert dialog.history_enabled.get_active()
        assert not dialog.history_full_path.get_active()
        dialog.history_full_path.set_active(True)
        assert app.settings is not None
        assert app.settings.get_boolean("history-full-path")
        history = app.history()
        assert history is not None
        assert history.full_path
        app.settings.reset("history-full-path")
        assert [row.get_title() for row in dialog._store_rows] == ["Incluidos en <b>berigna</b>"]
        dialog.show_store()  # rebuilt after a trusted list update
        assert len(dialog._store_rows) == 1

    drive(app, script)
