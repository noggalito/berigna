# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""The visible signature of a PDF (CU-02; BRG-UX-001 §3.2): the list of appearances and the
box on the preview, drawn with sample data while the user places it."""

import datetime as dt
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, Gtk  # noqa: E402

from berigna.core.appearance import (  # noqa: E402
    AppearanceKind,
    DniDisplay,
    StampData,
    VisibleSignature,
    render_appearance,
    stored_image,
)
from berigna.core.errors import AppearanceError  # noqa: E402
from berigna.ui.i18n import _  # noqa: E402
from berigna.ui.preview import PdfPreview  # noqa: E402
from berigna.ui.signing_form import APPEARANCES, DNI_SAMPLES, SignatureData  # noqa: E402
from berigna.ui.widgets import label_factory  # noqa: E402


class VisibleSignatureChoice:
    """Not visible or its appearance, and the box on ``preview``, which must have pages. The
    sample text follows the reason and location of ``data``. Whoever owns the preview calls
    :meth:`update` when the box moves (``PdfPreview.on_box_changed``)."""

    def __init__(
        self,
        preview: PdfPreview,
        data: SignatureData,
        settings: Gio.Settings | None,
        appearance_dir: Path | None,
    ) -> None:
        self._preview = preview
        self._data = data
        self._settings = settings
        self._appearance_dir = appearance_dir
        self.group = Adw.PreferencesGroup(
            title=_("Visible Signature"),
            description=_(
                "Drag the box to move it and its corner to resize it; drag the page to scroll "
                "it. In a box taller than wide, the image goes above the text."
            ),
        )
        labels = [_(label) for _kind, label in APPEARANCES]
        # The value goes in the subtitle, in full (see berigna.ui.preferences._combo).
        self.combo = Adw.ComboRow(
            title=_("Appearance"),
            model=Gtk.StringList.new(labels),
            factory=label_factory(visible=False),
            list_factory=label_factory(visible=True),
            subtitle_lines=0,
        )
        if settings is not None and settings.get_boolean("visible-signature"):
            kind = settings.get_string("appearance-kind")
            kinds = [k.value if k else None for k, _label in APPEARANCES]
            self.combo.set_selected(kinds.index(kind) if kind in kinds else 1)
        self.combo.connect("notify::selected", lambda *_a: self._on_visible())
        data.reason.connect(self.update)
        data.location.connect(self.update)
        self.group.add(self.combo)
        self._on_visible()

    def kind(self) -> AppearanceKind | None:
        """The chosen appearance; None: not visible."""
        return APPEARANCES[self.combo.get_selected()][0]

    def _dni(self) -> DniDisplay:
        settings = self._settings
        return DniDisplay(settings.get_string("appearance-dni") if settings else "last-four")

    def _image(self, kind: AppearanceKind) -> Path | None:
        directory = self._appearance_dir
        return stored_image(directory, kind) if directory is not None else None

    def _on_visible(self) -> None:
        preview = self._preview
        active = self.kind() is not None
        preview.set_box(preview.box or preview.default_box() if active else None)
        self.update()

    def signature(self) -> VisibleSignature | None:
        """What the core draws in the PDF; None: not visible."""
        kind = self.kind()
        return self._signature(kind, self._image(kind) if kind is not None else None)

    def _signature(
        self, kind: AppearanceKind | None, image: Path | None
    ) -> VisibleSignature | None:
        box = self._preview.box
        if box is None or kind is None:
            return None
        return VisibleSignature(
            box.page,
            (box.x, box.y, box.width, box.height),
            kind,
            image,
            self._data.language(),
            self._dni(),
        )

    def update(self) -> None:
        """Draw the appearance in the box with sample data: the real name and DNI come from
        the card when signing."""
        kind = self.kind()
        image = self._image(kind) if kind is not None else None  # looked up once per update
        visible = self._signature(kind, image)
        missing = kind in (AppearanceKind.RUBRIC, AppearanceKind.LOGO) and image is None
        label = _(APPEARANCES[self.combo.get_selected()][1])
        warning = _("Load the image in Preferences → Visible Signature.")
        self.combo.set_subtitle(f"{label}\n{warning}" if missing else label)
        if visible is None:
            self._preview.set_appearance(None)
            return
        sample = StampData(
            _("NAMES AND SURNAMES"),
            DNI_SAMPLES[visible.dni],
            dt.datetime.now().astimezone(),
            self._data.reason_value(),
            self._data.location_value(),
        )
        try:
            self._preview.set_appearance(render_appearance(visible, sample))
        except AppearanceError:
            self._preview.set_appearance(None)
