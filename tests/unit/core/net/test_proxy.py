# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Proxy of the HTTP requests (RF-064)."""

import pytest
import requests

from berigna.core.net import proxy
from berigna.core.net.proxy import ProxyMode, apply_proxy, valid_proxy_url


def test_manual_proxy_reaches_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    env: dict[str, str] = {"NO_PROXY": "localhost"}
    apply_proxy(ProxyMode.MANUAL, manual_url="http://proxy.example:3128", environ=env)
    assert env["https_proxy"] == env["HTTP_PROXY"] == "http://proxy.example:3128"
    assert "NO_PROXY" not in env
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    proxies = requests.utils.get_environ_proxies("https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml")
    assert proxies["https"] == "http://proxy.example:3128"


def test_manual_proxy_must_be_http() -> None:
    with pytest.raises(ValueError, match="not an HTTP"):
        apply_proxy(ProxyMode.MANUAL, manual_url="socks5://proxy:1080", environ={})
    assert not valid_proxy_url("http://")


def test_no_proxy_overrides_the_environment() -> None:
    env = {"HTTPS_PROXY": "http://corp:8080"}
    apply_proxy(ProxyMode.NONE, environ=env)
    assert env == {"no_proxy": "*", "NO_PROXY": "*"}


def test_system_proxy_from_the_desktop_or_the_session(monkeypatch: pytest.MonkeyPatch) -> None:
    env: dict[str, str] = {}
    apply_proxy(ProxyMode.SYSTEM, system_url="http://desktop:3128", environ=env)
    assert env["https_proxy"] == "http://desktop:3128"
    monkeypatch.setattr(proxy, "_SESSION", {"https_proxy": "http://session:8080"})
    env = {"HTTP_PROXY": "http://stale:1"}
    apply_proxy(ProxyMode.SYSTEM, system_url=None, environ=env)
    assert env == {"https_proxy": "http://session:8080"}
    apply_proxy(ProxyMode.SYSTEM, system_url="direct://", environ=env)
    assert env == {"https_proxy": "http://session:8080"}


def test_default_environment_is_the_process(monkeypatch: pytest.MonkeyPatch) -> None:
    fake: dict[str, str] = {"HTTPS_PROXY": "http://corp:8080"}
    monkeypatch.setattr(proxy, "process_environment", lambda: fake)
    apply_proxy(ProxyMode.NONE)
    assert fake == {"no_proxy": "*", "NO_PROXY": "*"}
