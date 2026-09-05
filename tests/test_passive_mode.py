import pytest
from fastapi.testclient import TestClient

from requestwatch.app import create_app
from requestwatch.config import Config


TOKEN = "passive-viewer-test-token"


def test_default_and_old_settings_upgrade_to_passive_observation(tmp_path, monkeypatch):
    monkeypatch.delenv("RW_PASSIVE_ONLY", raising=False)
    (tmp_path / "settings.json").write_text('{"capture_enabled":true}', encoding="utf-8")
    config = Config(data_dir=tmp_path, token=TOKEN)
    config.prepare()
    assert config.passive_only is True
    assert config.settings_values()["passive_only"] is True


def test_readonly_observes_full_http_without_rules_pause_or_action_side_effects(tmp_path, monkeypatch):
    app = create_app(Config(data_dir=tmp_path, token=TOKEN, demo=True, passive_only=True))
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + TOKEN
        rule = client.post("/api/rules", json={"name": "existing hold", "source": "http", "port": 8000})
        assert rule.status_code == 200
        body = "请求正文" * 300 + "REQUEST-END"
        record = app.state.runtime.ingest({"source": "http", "protocol": "HTTP", "dst_port": 8000,
            "method": "POST", "url": "http://example.test:8000/data", "request_body_text": body,
            "response_body_text": "响应正文-RESPONSE-END"}, can_intercept=True)
        assert record["state"] == "captured" and app.state.runtime.pending_count() == 0
        route = "/api/records/" + record["id"]
        assert client.get(route + "/body/request").text == body
        assert client.get(route + "/body/response").text == "响应正文-RESPONSE-END"
        assert client.get("/api/status").json()["passive_only"] is True
        before = app.state.store.stats()["captured_total"]
        for action, payload in (("replay", {"edits": {}}), ("decision", {"action": "drop"})):
            response = client.post(route + "/" + action, json=payload)
            assert response.status_code == 409 and "只读观察" in response.json()["detail"]
        assert app.state.store.stats()["captured_total"] == before
        assert app.state.store.get(record["id"])["state"] == "captured"


def test_panel_can_explicitly_enable_interactive_mode_without_changing_capture_data(tmp_path):
    app = create_app(Config(data_dir=tmp_path, token=TOKEN, demo=True, passive_only=True))
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + TOKEN
        assert client.get("/api/settings").json()["current"]["passive_only"] is True
        response = client.put("/api/settings", json={"passive_only": False})
        assert response.status_code == 200 and "passive_only" in response.json()["pending"]
        assert client.get("/api/status").json()["passive_only"] is True
        assert client.post("/api/settings/apply").status_code == 200
        assert client.get("/api/status").json()["passive_only"] is False
        client.post("/api/rules", json={"name": "explicit hold", "source": "http", "port": 8100})
        record = app.state.runtime.ingest({"source": "http", "protocol": "HTTP", "dst_port": 8100,
                                         "request_body_text": "review"}, can_intercept=True)
        assert record["state"] == "pending"
        assert client.post("/api/records/" + record["id"] + "/decision", json={"action": "drop"}).status_code == 200
        assert client.put("/api/settings", json={"passive_only": "true"}).status_code == 400
