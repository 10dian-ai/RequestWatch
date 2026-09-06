"""Regressions for panel preflight checks across listening addresses and families."""
from contextlib import contextmanager
import socket

from fastapi.testclient import TestClient
import pytest

from requestwatch.app import create_app
from requestwatch.config import Config


TOKEN = "settings-preflight-regression-token"


def require_ipv6_loopback():
    if not socket.has_ipv6:
        pytest.skip("IPv6 is unavailable")
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            probe.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback binding is unavailable")


@contextmanager
def occupied_listener(host, family=socket.AF_INET, port=0):
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        # Windows otherwise permits unrelated SO_REUSEADDR listeners to share a
        # port; exclusive binding models an ordinary already-owned server port.
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((host, port))
        listener.listen(1)
        yield listener.getsockname()[1]


def make_app(data_dir, port):
    return create_app(Config(data_dir=data_dir, token=TOKEN, host="127.0.0.1", port=port,
                             capture_enabled=False, proxy_enabled=False))


def assert_failed_apply_keeps_panel_editable(client, app, called, current_port):
    rejected = client.post("/api/settings/apply")
    assert rejected.status_code == 400, rejected.text
    assert "监听地址" in rejected.text or "端口" in rejected.text
    assert not called, "Rejected settings must not schedule a restart"
    assert app.state.config.host == "127.0.0.1"
    assert app.state.config.port == current_port
    assert app.state.config.token == TOKEN
    assert client.get("/api/status").status_code == 200
    assert client.get("/api/settings").status_code == 200
    # An unsuccessful attempt must not leave restart_scheduled set, which would
    # otherwise reject the user's attempt to repair their saved configuration.
    repaired = client.put("/api/settings", json={"host": "127.0.0.1", "port": current_port})
    assert repaired.status_code == 200, repaired.text


def test_localhost_checks_busy_ipv4_when_ipv6_resolves_first(tmp_path, monkeypatch):
    require_ipv6_loopback()
    original_getaddrinfo = socket.getaddrinfo
    lookups = []

    def dual_stack_localhost(host, port, *args, **kwargs):
        if host == "localhost":
            lookups.append((host, port))
            # Keep DNS order deterministic on machines whose hosts file differs.
            # Both addresses are real loopback addresses, and only IPv4 is busy.
            return (original_getaddrinfo("::1", port, *args, **kwargs)
                    + original_getaddrinfo("127.0.0.1", port, *args, **kwargs))
        return original_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", dual_stack_localhost)
    with occupied_listener("127.0.0.1") as current_port, occupied_listener("127.0.0.1") as busy_port:
        app = make_app(tmp_path, current_port)
        called = []
        app.state.request_restart = lambda: called.append(True)
        with TestClient(app) as client:
            client.headers["Authorization"] = "Bearer " + TOKEN
            saved = client.put("/api/settings", json={"host": "localhost", "port": busy_port})
            assert saved.status_code == 200, saved.text
            assert_failed_apply_keeps_panel_editable(client, app, called, current_port)
            assert lookups, "The hostname's full address list must be checked"


def test_current_ipv4_port_does_not_exempt_a_busy_ipv6_address(tmp_path):
    require_ipv6_loopback()
    with occupied_listener("127.0.0.1") as current_port:
        # Owning 127.0.0.1:P does not make an unrelated ::1:P listener our own.
        with occupied_listener("::1", family=socket.AF_INET6, port=current_port):
            app = make_app(tmp_path, current_port)
            called = []
            app.state.request_restart = lambda: called.append(True)
            with TestClient(app) as client:
                client.headers["Authorization"] = "Bearer " + TOKEN
                saved = client.put("/api/settings", json={"host": "::1"})
                assert saved.status_code == 200, saved.text
                assert_failed_apply_keeps_panel_editable(client, app, called, current_port)


def test_busy_newapi_reverse_port_rejects_apply_without_restart(tmp_path):
    with occupied_listener("127.0.0.1") as current_port, occupied_listener("127.0.0.1") as busy_port:
        app = make_app(tmp_path, current_port)
        called = []
        app.state.request_restart = lambda: called.append(True)
        with TestClient(app) as client:
            client.headers["Authorization"] = "Bearer " + TOKEN
            saved = client.put("/api/settings", json={"inspection_profile": "newapi", "proxy_enabled": True,
                "proxy_port": 48080, "newapi_upstream": "http://127.0.0.1:3000", "newapi_reverse_port": busy_port})
            assert saved.status_code == 200, saved.text
            assert_failed_apply_keeps_panel_editable(client, app, called, current_port)
