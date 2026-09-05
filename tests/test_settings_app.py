import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from requestwatch.app import create_app
from requestwatch.config import Config
from requestwatch.settings import SettingsStore


def available_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def test_panel_settings_demo_secrets_and_isolation(tmp_path):
    real_token = "original-production-token"
    (tmp_path / "admin-token").write_text(real_token)
    app = create_app(Config(data_dir=tmp_path, token="panel-demo-token", demo=True))
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer panel-demo-token"
        assert client.get("/api/settings", headers={"Authorization": ""}).status_code == 401
        original = client.get("/api/settings").json()
        assert original["current"]["port"] == 7030 and original["restart_supported"]
        changed = client.put("/api/settings", json={"port": 17030, "max_records": 500,
                            "token": "new-secret-demo-token", "proxy_auth": "user:secret-password"})
        assert changed.status_code == 200
        assert "secret-password" not in changed.text and "new-secret-demo-token" not in changed.text
        assert changed.json()["current"]["port"] == 7030
        assert changed.json()["saved"]["port"] == 17030
        assert "port" in changed.json()["pending"]
        assert client.post("/api/settings/apply").json()["restarting"] is False
        assert client.get("/api/settings").json()["pending"] == []
        assert app.state.config.port == 7030 and app.state.config.token == "panel-demo-token"
        assert (tmp_path / "admin-token").read_text() == real_token
        assert not (tmp_path / "settings.json").exists()
        assert (tmp_path / "demo/settings.json").exists()
        invalid = client.put("/api/settings", json={"token": "private-short"})
        assert invalid.status_code == 400 and "private-short" not in invalid.text
        assert client.put("/api/settings", json={"data_dir": "/elsewhere"}).status_code == 400
        assert client.put("/api/settings", json={"proxy_auth": ""}).json()["saved"]["proxy_auth_configured"] is False


def test_settings_override_environment_and_preserve_empty_protected_list(tmp_path, monkeypatch):
    monkeypatch.setenv("RW_PORT", "12345")
    store = SettingsStore(tmp_path)
    store.save({"port": 17031, "protected_ports": [], "token": "saved-settings-token", "proxy_enabled": False})
    config = Config(data_dir=tmp_path, token="environment-token")
    config.prepare()
    assert config.port == 17031
    assert config.token == "saved-settings-token"
    assert config.settings_values()["protected_ports"] == []
    assert set(config.protected_ports) == {17031, config.proxy_port}
    assert (tmp_path / "admin-token").read_text().strip() == config.token


def test_real_cli_panel_restart_changes_port_token_and_runtime_settings(tmp_path):
    first_port, next_port = available_port(), available_port()
    while next_port == first_port:
        next_port = available_port()
    token, new_token = "cli-settings-old-token", "cli-settings-new-token"
    environment = os.environ.copy()
    environment.update(RW_TOKEN=token, RW_CAPTURE="false", RW_PROXY="false")
    directory = tmp_path / "runtime"
    log = (tmp_path / "server.log").open("wb")
    process = subprocess.Popen([sys.executable, "-m", "requestwatch", "--host", "127.0.0.1", "--port", str(first_port),
                                "--data-dir", str(directory), "--no-capture", "--no-proxy"], env=environment,
                               stdout=log, stderr=subprocess.STDOUT,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    def ready(port, previous_id=None):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail("Temporary CLI exited: " + (tmp_path / "server.log").read_text(errors="replace"))
            try:
                response = httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=.5, trust_env=False)
                if response.status_code == 200 and response.json()["instance_id"] != previous_id:
                    return response.json()["instance_id"]
            except (httpx.HTTPError, ValueError):
                pass
            time.sleep(.05)
        pytest.fail("Temporary CLI failed to become ready")
    try:
        initial_id = ready(first_port)
        with httpx.Client(base_url=f"http://127.0.0.1:{first_port}", headers={"Authorization": "Bearer " + token}, trust_env=False) as admin:
            settings = admin.get("/api/settings").json()
            assert settings["restart_supported"] and not settings["demo"]
            update = admin.put("/api/settings", json={"port": next_port, "token": new_token,
                               "max_records": 321, "pending_limit": 19, "default_timeout_seconds": 17,
                               "tcp_idle_timeout": 456, "queue_num": 17033, "protected_ports": [22, 55]})
            assert update.status_code == 200, update.text
            assert token not in update.text and new_token not in update.text
            assert admin.get("/api/status").json()["port"] == first_port
            applied = admin.post("/api/settings/apply")
            assert applied.status_code == 200 and applied.json()["restarting"]
        assert ready(next_port, initial_id) != initial_id
        with httpx.Client(base_url=f"http://127.0.0.1:{next_port}", headers={"Authorization": "Bearer " + new_token}, trust_env=False) as admin:
            current = admin.get("/api/settings").json()
            assert current["current"]["port"] == next_port and current["pending"] == []
            assert current["current"]["max_records"] == 321 and current["current"]["pending_limit"] == 19
            assert current["current"]["tcp_idle_timeout"] == 456
            assert admin.get("/api/status", headers={"Authorization": "Bearer " + token}).status_code == 401
            rule = admin.post("/api/rules", json={"name": "default timeout", "port": 8888}).json()
            assert rule["timeout_seconds"] == 17
            assert (directory / "admin-token").read_text().strip() == new_token
            assert json.loads((directory / "runtime.json").read_text())["active_queue_num"] == 17033
            with socket.socket() as occupied:
                occupied.bind(("127.0.0.1", 0))
                occupied.listen(1)
                busy_port = occupied.getsockname()[1]
                assert admin.put("/api/settings", json={"port": busy_port}).status_code == 200
                rejected = admin.post("/api/settings/apply")
                assert rejected.status_code == 400 and "端口" in rejected.text
                assert admin.get("/api/status").status_code == 200
            assert admin.put("/api/settings", json={"port": next_port}).status_code == 200
            # Simulate another process taking the port after preflight but before restart.
            rollback_port = available_port()
            before_rollback = admin.get("/healthz").json()["instance_id"]
            assert admin.put("/api/settings", json={"port": rollback_port, "token": "should-rollback-token"}).status_code == 200
            assert admin.post("/api/settings/apply").status_code == 200
            with socket.socket() as raced:
                raced.bind(("127.0.0.1", rollback_port))
                raced.listen(1)
                ready(next_port, before_rollback)
                restored = admin.get("/api/settings")
                assert restored.status_code == 200, restored.text
                assert restored.json()["restart_rollback"]
                assert restored.json()["current"]["port"] == next_port
                assert restored.json()["pending"] == []
                assert admin.get("/api/status", headers={"Authorization": "Bearer should-rollback-token"}).status_code == 401
                assert (directory / "admin-token").read_text().strip() == new_token
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()
