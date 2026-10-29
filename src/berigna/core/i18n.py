# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Languages of berigna 1.0 and their gettext catalogues (ADR-0011, ADR-0015).

Two languages: Peruvian Spanish (``es_PE``) and Southern Quechua (``quz_PE``, catalogue
``quz``). Source strings are written in English, as gettext expects, but English is not
offered in 1.0: whatever is not Quechua is shown in es_PE, and a Quechua string still waiting
for the translators falls back to es_PE as well, never to the English source.

Catalogues are looked up in ``$BERIGNA_LOCALEDIR`` when set (development and tests, where
``scripts/traducciones.sh compilar`` writes them to ``build/locale``) and otherwise in the
system directory (``/usr/share/locale`` in the package). A missing catalogue (an incomplete
installation) does not stop the program: the untranslated source comes back, which the
explanations detect and leave empty, so no language is mixed.
"""

import enum
import gettext
import os
import re
from collections.abc import Mapping, Sequence

DOMAIN = "berigna"
# The program's name as a word of a sentence, which the interface and the reports set in bold
# (decision of 2026-10-28); not inside a file name such as "berigna-prueba.pdf". Quechua adds
# its suffixes to the name ("berignaqa", "berignawan"): only "berigna" is matched.
NAME = re.compile(r"(?<![\w./-])berigna(?=[a-zñ']*(?![\w/-]|\.\w))")


class Language(enum.Enum):
    ES_PE = "es_PE"
    QUZ_PE = "quz_PE"

    @property
    def catalogue(self) -> str:
        return "quz" if self is Language.QUZ_PE else "es_PE"


_QUECHUA_PREFIXES = ("quz", "quy", "qu")


def _is_quechua(tag: str) -> bool:
    language = tag.split(".")[0].split("@")[0].split("_")[0].lower()
    return language in _QUECHUA_PREFIXES


def _is_spanish(tag: str) -> bool:
    return tag.split("_")[0].lower() == "es"


def resolve_language(preferences: Sequence[str]) -> Language:
    """Pick the language for the user's ordered ``preferences`` (``es_MX``, ``quz_PE``…).

    The first preference that berigna offers wins; anything else ends in es_PE.
    """
    for tag in preferences:
        if _is_quechua(tag):
            return Language.QUZ_PE
        if _is_spanish(tag):
            return Language.ES_PE
    return Language.ES_PE


def system_preferences(environ: Mapping[str, str] | None = None) -> list[str]:
    """The user's language preferences, in the order gettext reads them."""
    env = os.environ if environ is None else environ
    for name in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        value = env.get(name, "")
        if value:
            return [tag for tag in value.split(":") if tag]
    return []


def localedir() -> str | None:
    return os.environ.get("BERIGNA_LOCALEDIR") or None


def translations(language: Language, *, strict: bool = False) -> gettext.NullTranslations:
    """Catalogue for ``language``; Quechua falls back to es_PE unless ``strict``.

    ``strict`` returns the Quechua catalogue alone, so that a missing translation shows as the
    untranslated source and can be detected (the JSON report leaves it empty).
    """
    spanish = _catalogue(Language.ES_PE)
    if language is Language.ES_PE:
        return spanish
    quechua = _catalogue(Language.QUZ_PE)
    if not strict:
        quechua.add_fallback(spanish)
    return quechua


def _catalogue(language: Language) -> gettext.NullTranslations:
    return gettext.translation(DOMAIN, localedir(), languages=[language.catalogue], fallback=True)
