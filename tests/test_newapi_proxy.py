import asyncio
import os
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from requestwatch.config import Config
from requestwatch.network import NetworkEngine
from requestwatch.proxy import ProxyProcess
from requestwatch.proxy_addon import RequestWatchAddon
from requestwatch.settings import SettingsInput, validate_settings, SettingsError
from test_proxy import flow


@pytest.mark.parametrize("value", ["http://new-api:3000", "https://newapi.example.test", "http://[::1]:3000"])
def test_newapi_origin_accepts_compose_service_and_host_urls(value):
    assert SettingsInput(newapi_upstream=value + "/").newapi_upstream == value


@pytest.mark.parametrize("value", ["new-api:3000", "ftp://host", "http://", "http://host/path", "http://host?x=1",
    "http://host#part", "http://host?", "http://host#", "http://user:secret@host", "http://host:0",
    "http://host:70000", "http://bad host", "http://host/\\oops", " http://host", "http://host\n"])
def test_newapi_origin_rejects_ambiguous_or_authenticated_targets(value):
    with pytest.raises(ValidationError):
        SettingsInput(newapi_upstream=value)


@pytest.mark.parametrize("updates", [{"inspection_profile":"other"}, {"inspection_profile": True},
    {"newapi_reverse_port": "8081"}, {"newapi_reverse_port": 0}, {"newapi_reverse_port":65536},
    {"newapi_reverse_port":8080,"proxy_port":8080,"newapi_upstream":"http://new-api:3000"}, {"newapi_reverse_port":7030,"port":7030,"newapi_upstream":"http://new-api:3000"}])
def test_newapi_settings_are_strict_and_listen_ports_distinct(updates):
    with pytest.raises(ValidationError):
        SettingsInput.model_validate(updates)


def test_partial_reverse_port_change_checks_current_listeners():
    with pytest.raises(SettingsError):
        validate_settings({"newapi_reverse_port":7030}, {"port":7030,"proxy_port":8080,"newapi_upstream":"http://new-api:3000"})


def test_newapi_profile_defaults_to_no_host_capture_or_queue(tmp_path):
    config = Config(data_dir=tmp_path, token="newapi-capture-fixture-token", passive_only=False)
    config.prepare()
    assert config.inspection_profile == "newapi"
    assert config.newapi_reverse_port == 8081 and 8081 not in config.protected_ports
    def forbidden(*args, **kwargs):
        raise AssertionError("New API profile must not sniff, queue, or change firewall rules")
    runtime = SimpleNamespace(rules=lambda:[{"source":"packet","enabled":True}])
    engine = NetworkEngine(runtime, config, runner=forbidden, queue_factory=forbidden,
                           sniffer_factory=forbidden, interface_provider=forbidden, platform_name="linux")
    engine.start()
    engine._enable_queue()
    assert engine._thread is None and engine._sniffer is None and not engine._rules_need_queue()
    status = engine.status()
    assert status["capture_mode"] == "newapi" and status["configured_enabled"]
    assert not status["enabled"] and not status["capture_running"]
    assert "全机抓包已停用" in status["message"]


def test_dual_proxy_children_keep_reverse_auth_independent_and_stop_both(tmp_path, monkeypatch):
    from requestwatch import proxy as module
    children = []
    class Child:
        returncode = None
        def __init__(self, command, **kwargs):
            self.command, self.options = command, kwargs
            self.pid = len(children) + 100
            children.append(self)
        def poll(self): return self.returncode
        def terminate(self): self.returncode = 0
        def wait(self, timeout): return self.returncode
    monkeypatch.setattr(module.subprocess, "Popen", Child)
    config = Config(data_dir=tmp_path, token="fixture-private-admin-token", proxy_auth="operator:password",
                    newapi_upstream="http://new-api:3000")
    process = ProxyProcess(config)
    monkeypatch.setattr(process, "_executable", lambda:"mitmdump")
    status = process.start()
    assert len(children) == 2 and status["running"] and status["reverse"]["running"]
    upstream, client = children
    assert upstream.options["env"]["RW_CAPTURE_LEG"] == "upstream"
    assert client.options["env"]["RW_CAPTURE_LEG"] == "client"
    assert "proxyauth=operator:password" in upstream.command
    assert "proxyauth=operator:password" not in client.command
    assert "proxyauth=" in client.command and "keep_host_header=true" in client.command
    assert "reverse:http://new-api:3000" in client.command
    assert not status["reverse"]["authenticated"]
    process.start()
    assert len(children) == 2
    client.returncode = 1
    assert "proxy-reverse.log" in process.status()["error"]
    process.start()
    assert len(children) == 3 and process.status()["error"] is None
    process.stop()
    assert all(child.returncode is not None for child in children)
    assert not process.status()["running"] and not process.status()["reverse"]["running"]


@pytest.mark.parametrize("profile,target", [("newapi", ""), ("network", "http://new-api:3000")])
def test_reverse_stays_disabled_without_enabled_profile_and_target(tmp_path, profile, target):
    process = ProxyProcess(Config(data_dir=tmp_path, inspection_profile=profile, newapi_upstream=target))
    assert process.status()["reverse"]["enabled"] is False


@pytest.mark.parametrize("leg", ["client", "upstream"])
def test_addon_marks_record_capture_leg_without_changing_body(monkeypatch, leg):
    monkeypatch.setenv("RW_CAPTURE_LEG", leg)
    async def run():
        captured = {}
        addon = RequestWatchAddon()
        async def api(method, path, data=None, **kwargs):
            if method == "POST" and path == "/api/internal/ingest":
                captured.update(data)
            return {"id":"fixture","state":"captured"}
        addon._api = api
        item = flow()
        original = item.request.raw_content
        await addon.request(item)
        assert captured["capture_leg"] == leg and item.request.raw_content == original
        item.error = "fixture end"
        await addon.error(item)
        if addon._tasks:
            await asyncio.gather(*list(addon._tasks))
        await asyncio.wait_for(addon._heartbeat_task, timeout=1)
    asyncio.run(run())


@pytest.mark.parametrize("disabled", [{"newapi_upstream":""}, {"proxy_enabled":False}, {"inspection_profile":"network"}])
def test_disabled_reverse_does_not_reserve_port_or_break_existing_config(tmp_path, disabled):
    values = {"proxy_port":8081,"newapi_reverse_port":8081,"newapi_upstream":"http://new-api:3000", **disabled}
    assert validate_settings(values) == SettingsInput.model_validate(values).model_dump(exclude_unset=True)
    config = Config(data_dir=tmp_path, token="reverse-compat-fixture-token", **values)
    config.prepare()
    assert config.proxy_port == 8081
    assert not ProxyProcess(config).status()["reverse"]["enabled"]
    ordinary = Config(data_dir=tmp_path / "ordinary", token="reverse-compat-fixture-token", **disabled)
    ordinary.prepare()
    assert 8081 not in ordinary.protected_ports


def test_enabled_reverse_port_is_automatically_protected(tmp_path):
    config = Config(data_dir=tmp_path, token="reverse-compat-fixture-token", newapi_upstream="http://new-api:3000")
    config.prepare()
    assert 8081 in config.protected_ports


@pytest.mark.parametrize("upstream", ["http://localhost:8080", "http://127.0.0.2:8081", "http://[::1]:7030", "http://192.0.2.5:8081"])
def test_reverse_cannot_point_back_to_its_own_listeners(upstream):
    with pytest.raises(SettingsError, match="自身"):
        validate_settings({"newapi_upstream":upstream}, {"proxy_host":"192.0.2.5"})


def test_remote_service_can_use_same_port_number_as_proxy():
    assert validate_settings({"newapi_upstream":"http://remote-api:8081"})["newapi_upstream"] == "http://remote-api:8081"
