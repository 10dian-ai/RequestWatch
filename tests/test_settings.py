import json
import os
from pathlib import Path
import stat
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from requestwatch.settings import (
    MAX_SETTINGS_BYTES, SETTING_NAMES, SettingsError, SettingsInput, SettingsStore,
    public_settings, validate_settings,
)


TOKEN = "settings-unit-secret-token-32-chars"
AUTH = "tester:private-password"


def test_all_fields_validate_and_normalize():
    settings = SettingsInput(
        host="0.0.0.0", port=7030, interfaces=["eth0", "docker0", "eth0"],
        capture_enabled=True, queue_num=7030, protected_ports=[8080, 22, 22],
        proxy_enabled=False, proxy_host="::1", proxy_port=8080, proxy_auth=AUTH,
        max_records=20000, pending_limit=256, mitmdump="/opt/requestwatch/.venv/bin/mitmdump",
        token=TOKEN, default_timeout_seconds=45, tcp_idle_timeout=600,
    )
    values = settings.model_dump(exclude_unset=True)
    assert set(values) == SETTING_NAMES
    assert values["interfaces"] == "eth0,docker0"
    assert values["protected_ports"] == [22, 8080]
    assert settings.proxy_enabled is False
    assert TOKEN not in repr(settings) and AUTH not in repr(settings)


@pytest.mark.parametrize("field", sorted(SETTING_NAMES))
def test_explicit_null_is_rejected_for_every_setting(field):
    with pytest.raises(ValidationError):
        SettingsInput.model_validate({field: None})


@pytest.mark.parametrize("field", [
    "port", "queue_num", "proxy_port", "max_records", "pending_limit",
    "default_timeout_seconds", "tcp_idle_timeout",
])
@pytest.mark.parametrize("value", [True, False, "7030", 7030.0, [], {}])
def test_integer_settings_do_not_coerce_types(field, value):
    with pytest.raises(ValidationError):
        SettingsInput.model_validate({field: value})


@pytest.mark.parametrize("field", ["capture_enabled", "proxy_enabled"])
@pytest.mark.parametrize("value", [0, 1, "true", "false", [], {}])
def test_boolean_settings_do_not_coerce_types(field, value):
    with pytest.raises(ValidationError):
        SettingsInput.model_validate({field: value})


@pytest.mark.parametrize("field", ["host", "proxy_host", "proxy_auth", "token", "mitmdump"])
@pytest.mark.parametrize("value", [0, 1.5, True, [], {}, b"raw bytes"])
def test_string_settings_do_not_coerce_types(field, value):
    with pytest.raises(ValidationError):
        SettingsInput.model_validate({field: value})


@pytest.mark.parametrize("field,value", [
    ("port", 0), ("port", 65536), ("queue_num", -1), ("queue_num", 65536),
    ("proxy_port", 0), ("proxy_port", 65536), ("max_records", 99), ("max_records", 1_000_001),
    ("pending_limit", 0), ("pending_limit", 10001), ("default_timeout_seconds", 4),
    ("default_timeout_seconds", 121), ("tcp_idle_timeout", 29), ("tcp_idle_timeout", 86401),
])
def test_numeric_setting_bounds(field, value):
    with pytest.raises(ValidationError):
        SettingsInput.model_validate({field: value})


@pytest.mark.parametrize("host", ["127.0.0.1", "0.0.0.0", "::", "::1", "fe80::1%eth0", "localhost", "proxy.internal", "host-name."])
def test_valid_listen_addresses(host):
    assert SettingsInput(host=host, proxy_host=host).host == host


@pytest.mark.parametrize("host", [
    "", " 127.0.0.1", "127.0.0.1 ", "127.0.0.1\n", "localhost\r\nInjected: yes",
    "http://127.0.0.1", "127.0.0.1:7030", "[::]", "*", "999.999.1.1", "127.0.0",
    "-bad.local", "bad-.local", "bad..local", "bad.local..", "bad_host", "../socket", "fe80::1%bad/interface",
])
def test_invalid_listen_addresses(host):
    with pytest.raises(ValidationError):
        SettingsInput(host=host)


@pytest.mark.parametrize("value,expected", [
    ("any", "any"), ("all", "any"), (["all"], "any"),
    ("eth0, docker0,eth0", "eth0,docker0"), (["eth0", "lo"], "eth0,lo"),
    ("br-123456789abc", "br-123456789abc"),
])
def test_interface_inputs_are_normalized(value, expected):
    assert SettingsInput(interfaces=value).interfaces == expected


@pytest.mark.parametrize("value", [
    "", "eth0,", "any,eth0", "all,any", "../../eth0", "eth0;echo", "eth0 eth1",
    "x" * 16, "eth0\n", ["eth0\r"], [], [""], [1], [True], ["any", "lo"],
    ["lo"] * 65, 1, True, {"name": "eth0"}, ("eth0",), b"eth0",
])
def test_invalid_interfaces_are_rejected(value):
    with pytest.raises(ValidationError):
        SettingsInput(interfaces=value)


@pytest.mark.parametrize("value", ["22,80", ["22"], [True], [0], [65536], {}, (22,), [22.0], list(range(1, 1026))])
def test_protected_port_types_and_bounds(value):
    with pytest.raises(ValidationError):
        SettingsInput(protected_ports=value)


def test_empty_extra_protected_ports_are_allowed():
    assert SettingsInput(protected_ports=[]).protected_ports == []


@pytest.mark.parametrize("auth", ["tester", ":password", "tester:", "tester:pass\n", "tester:pass\x00word"])
def test_proxy_auth_requires_basic_credentials_without_controls(auth):
    with pytest.raises(ValidationError):
        SettingsInput(proxy_auth=auth)


def test_proxy_auth_can_clear_or_contain_colons_in_password():
    assert SettingsInput(proxy_auth="").proxy_auth == ""
    assert SettingsInput(proxy_auth="tester:pass:word").proxy_auth == "tester:pass:word"


@pytest.mark.parametrize("token", ["", "short", "x" * 513, "prefix secret token", "x" * 16 + "\n", "非ASCII访问令牌足够长度一二三四五"])
def test_token_requires_suitable_header_value(token):
    with pytest.raises(ValidationError):
        SettingsInput(token=token)


@pytest.mark.parametrize("value", ["", "mitmdump", "/opt/requestwatch/.venv/bin/mitmdump", "C:/Program Files/mitmproxy/mitmdump.exe", ".proxy-venv/bin/mitmdump"])
def test_mitmdump_accepts_only_a_single_executable_value(value):
    assert SettingsInput(mitmdump=value).mitmdump == value


@pytest.mark.parametrize("value", [" mitmdump", "mitmdump ", "mitmdump\n", "mitmdump\x00", "mitmdump --set ssl_insecure=true", "--listen-port"])
def test_mitmdump_rejects_control_characters_and_command_options(value):
    with pytest.raises(ValidationError):
        SettingsInput(mitmdump=value)


@pytest.mark.parametrize("value", [None, [], "settings", 7, {"data_dir": "/elsewhere"}, {"unknown": True}])
def test_only_a_whitelisted_settings_object_is_accepted(value):
    with pytest.raises(ValidationError):
        SettingsInput.model_validate(value)


def test_cross_field_port_validation_uses_effective_environment_defaults():
    with pytest.raises(ValidationError):
        SettingsInput(port=7030, proxy_port=7030)
    with pytest.raises(SettingsError):
        validate_settings({"port": 8080})
    with pytest.raises(SettingsError):
        validate_settings({"port": 9090}, base={"proxy_port": 9090})
    assert validate_settings({"port": 8080}, base={"proxy_port": 9090}) == {"port": 8080}
    assert validate_settings({"max_records": 5000}, base={"port": 7030, "proxy_port": 8080, "token": ""}) == {"max_records": 5000}


def test_missing_settings_returns_no_overrides_and_does_not_create_file(tmp_path):
    store = SettingsStore(tmp_path / "not-created")
    assert store.load() == {}
    assert not store.path.exists()
    assert not store.root.exists()


def test_partial_settings_persist_across_restart_and_preserve_secrets(tmp_path):
    store = SettingsStore(tmp_path)
    store.save({"host": "0.0.0.0", "token": TOKEN, "proxy_auth": AUTH})
    changed = store.save(SettingsInput(max_records=30000))
    assert changed == {"host": "0.0.0.0", "token": TOKEN, "proxy_auth": AUTH, "max_records": 30000}
    assert SettingsStore(tmp_path).load() == changed
    assert "capture_enabled" not in json.loads(store.path.read_text(encoding="utf-8"))
    assert store.save({"proxy_auth": ""})["proxy_auth"] == ""
    assert store.load()["token"] == TOKEN


def test_load_saved_overrides_does_not_assume_environment_defaults(tmp_path):
    store = SettingsStore(tmp_path)
    store.save({"port": 8080}, base={"proxy_port": 9090})
    assert store.load() == {"port": 8080}
    with pytest.raises(SettingsError):
        store.save({"pending_limit": 200}, base={"proxy_port": 8080})
    assert store.load() == {"port": 8080}


def test_public_views_never_return_secret_values_or_unlisted_keys(tmp_path):
    store = SettingsStore(tmp_path)
    store.save({"token": TOKEN, "proxy_auth": AUTH, "port": 7030})
    public = store.public()
    assert public == {"port": 7030, "token_configured": True, "proxy_auth_configured": True}
    assert TOKEN not in json.dumps(public) and AUTH not in json.dumps(public)
    projected = public_settings({"token": TOKEN, "proxy_auth": AUTH, "private_unknown": TOKEN, "protected_ports": (22, 7030)})
    assert projected["protected_ports"] == [22, 7030]
    assert "private_unknown" not in projected
    assert "token" not in projected and "proxy_auth" not in projected
    assert public_settings(SettingsInput(proxy_auth=""))["proxy_auth_configured"] is False


@pytest.mark.parametrize("payload", [
    b"not-json", b"{", b"[]", b"null", b'{"unknown": true}', b'{"port":"7030"}',
    b'{"proxy_enabled":1}', b'{"token":null}', b'{"port":7030,"port":8080}',
    b'{"port":7030,"proxy_port":7030}', b"\xff",
])
def test_corrupt_settings_are_explicit_errors_and_never_overwritten(tmp_path, payload):
    store = SettingsStore(tmp_path)
    store.path.write_bytes(payload)
    with pytest.raises(SettingsError):
        store.load()
    with pytest.raises(SettingsError):
        store.save({"port": 9090})
    assert store.path.read_bytes() == payload


def test_excessively_large_settings_file_is_rejected(tmp_path):
    store = SettingsStore(tmp_path)
    store.path.write_bytes(b" " * (MAX_SETTINGS_BYTES + 1))
    with pytest.raises(SettingsError, match="64 KiB"):
        store.load()


def test_invalid_secret_in_corrupt_settings_is_not_in_error_message(tmp_path):
    store = SettingsStore(tmp_path)
    sensitive = "private-token-with-invalid newline\n"
    store.path.write_text(json.dumps({"token": sensitive}), encoding="utf-8")
    with pytest.raises(SettingsError) as error:
        store.load()
    assert sensitive not in str(error.value)
    assert "private-token" not in str(error.value)


def test_failed_atomic_replace_preserves_previous_file_and_cleans_temporary(tmp_path):
    store = SettingsStore(tmp_path)
    store.save({"port": 7030, "token": TOKEN})
    original = store.path.read_bytes()
    with patch("requestwatch.settings.os.replace", side_effect=OSError("disk full")):
        with pytest.raises(SettingsError, match="无法保存"):
            store.save({"port": 9090})
    assert store.path.read_bytes() == original
    assert not list(tmp_path.glob(".settings-*.tmp"))
    assert store.load()["port"] == 7030


def test_failed_data_sync_preserves_previous_file_and_cleans_temporary(tmp_path):
    store = SettingsStore(tmp_path)
    store.save({"port": 7030})
    original = store.path.read_bytes()
    with patch("requestwatch.settings.os.fsync", side_effect=OSError("disk full")):
        with pytest.raises(SettingsError, match="无法保存"):
            store.save({"port": 9090})
    assert store.path.read_bytes() == original
    assert not list(tmp_path.glob(".settings-*.tmp"))


def test_file_is_complete_before_atomic_replacement(tmp_path):
    store = SettingsStore(tmp_path)
    original_replace = os.replace
    staged = []

    def observe(source, destination):
        staged.append(json.loads(Path(source).read_text(encoding="utf-8")))
        assert Path(source).parent == tmp_path
        return original_replace(source, destination)

    with patch("requestwatch.settings.os.replace", side_effect=observe):
        result = store.save({"token": TOKEN, "proxy_auth": AUTH, "port": 9090})
    assert staged == [result]
    assert store.load() == result


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are not enforced on Windows")
def test_private_permissions_on_new_and_replaced_settings_file(tmp_path):
    store = SettingsStore(tmp_path)
    store.save({"token": TOKEN})
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    store.path.chmod(0o644)
    store.save({"port": 9090})
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_concurrent_partial_updates_do_not_lose_other_fields(tmp_path):
    store = SettingsStore(tmp_path)
    values = [{"port": 9090}, {"max_records": 5000}, {"pending_limit": 200}, {"token": TOKEN}]
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(store.save, values))
    assert store.load() == {key: value for partial in values for key, value in partial.items()}


def test_settings_directory_is_rejected_as_a_file(tmp_path):
    store = SettingsStore(tmp_path)
    store.path.mkdir()
    with pytest.raises(SettingsError):
        store.load()
    with pytest.raises(SettingsError):
        store.save({"port": 9090})


def test_symlink_settings_cannot_read_or_overwrite_outside_file(tmp_path):
    target = tmp_path / "outside.json"
    target.write_text(json.dumps({"token": TOKEN}), encoding="utf-8")
    store = SettingsStore(tmp_path / "data")
    store.root.mkdir()
    try:
        store.path.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Creating symlinks is unavailable on this host")
    before = target.read_bytes()
    with pytest.raises(SettingsError):
        store.load()
    with pytest.raises(SettingsError):
        store.save({"token": "replacement-secret-token"})
    assert target.read_bytes() == before


@pytest.mark.parametrize("values", [{"port": "7030"}, {"host": "http://localhost"}, {"unknown": True}, {"token": "private-secret-with-space "}])
def test_save_validation_errors_have_uniform_safe_api_type(tmp_path, values):
    store = SettingsStore(tmp_path)
    with pytest.raises(SettingsError) as error:
        store.save(values)
    assert "private-secret" not in str(error.value)
    assert not store.path.exists()
