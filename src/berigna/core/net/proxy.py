# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""The proxy of every HTTP request berigna makes: OCSP, CRL, TSA and TSL (RF-064).

``requests`` reads the standard environment variables on every request, also inside
pyhanko-certvalidator, which does not let callers pass a proxy. So the setting is applied to
those variables, once for the whole process:

- ``system``: the proxy of the desktop (the interface asks GIO and passes it here), or, if
  the desktop has none, whatever the session environment already had;
- ``manual``: the URL of the preferences (``proxy-url``), HTTP or HTTPS;
- ``none``: direct connections, even if the environment names a proxy.
"""

import enum
import os
from collections.abc import MutableMapping

_PROXY_VARIABLES = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")
_BYPASS_VARIABLES = ("no_proxy", "NO_PROXY")
_SESSION = {
    name: os.environ[name] for name in _PROXY_VARIABLES + _BYPASS_VARIABLES if name in os.environ
}


class ProxyMode(enum.Enum):
    SYSTEM = "system"
    MANUAL = "manual"
    NONE = "none"


def process_environment() -> MutableMapping[str, str]:
    """The environment ``requests`` reads; a function so that tests can replace it."""
    return os.environ


def valid_proxy_url(url: str) -> bool:
    return url.startswith(("http://", "https://")) and len(url) > len("https://")


def apply_proxy(
    mode: ProxyMode,
    *,
    manual_url: str = "",
    system_url: str | None = None,
    environ: MutableMapping[str, str] | None = None,
) -> None:
    """Set the proxy of the process. Raises ValueError for a manual URL that is not HTTP(S)."""
    env = process_environment() if environ is None else environ
    for name in _PROXY_VARIABLES + _BYPASS_VARIABLES:
        env.pop(name, None)
    if mode is ProxyMode.NONE:
        env["no_proxy"] = env["NO_PROXY"] = "*"
    elif mode is ProxyMode.MANUAL:
        if not valid_proxy_url(manual_url):
            raise ValueError(f"not an HTTP(S) proxy URL: {manual_url!r}")
        for name in _PROXY_VARIABLES:
            env[name] = manual_url
    elif system_url is not None and valid_proxy_url(system_url):
        for name in _PROXY_VARIABLES:
            env[name] = system_url
    else:
        env.update(_SESSION)
