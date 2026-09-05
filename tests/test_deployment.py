"""Exercise deployment scripts with command stubs; never run apt or systemd."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from types import SimpleNamespace
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[1]


def bash_path():
    if os.name == "nt":
        git = shutil.which("git")
        if git:
            candidate = Path(git).resolve().parents[1] / "bin" / "bash.exe"
            if candidate.exists():
                return str(candidate)
        return None  # Avoid accidentally invoking the Windows WSL launcher.
    return shutil.which("bash")


BASH = bash_path()
pytestmark = pytest.mark.skipif(BASH is None, reason="Bash is required for deployment script tests")


def posix(path: Path) -> str:
    value = path.resolve().as_posix()
    if os.name == "nt":
        return "/" + value[0].lower() + value[2:]
    return value


def write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(0o755)


@pytest.fixture
def shell(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    release = tmp_path / "os-release"
    write(release, 'ID=ubuntu\nVERSION_ID="24.04"\n')
    env = os.environ.copy()
    env.update({
        "PATH": str(bin_dir) + os.pathsep + env.get("PATH", ""),
        "TEST_COMMAND_LOG": posix(tmp_path / "commands.log"),
        "TEST_INSTALL_MARKER": posix(tmp_path / "installed"),
        "TEST_REAL_PYTHON": posix(Path(sys.executable)),
        "MSYS_NO_PATHCONV": "1",
        "MSYS2_ARG_CONV_EXCL": "*",
    })
    env.pop("RW_REF", None)
    bash_env = tmp_path / "bash-env"
    write(bash_env, 'export PATH="$TEST_BIN_DIR:$PATH"\n')
    env["BASH_ENV"] = posix(bash_env)
    env["TEST_BIN_DIR"] = posix(bin_dir)
    common = '#!/usr/bin/env bash\nset -eu\nprintf "%s %s\\n" "$(basename "$0")" "$*" >> "$TEST_COMMAND_LOG"\n'
    write(bin_dir / "id", '#!/usr/bin/env bash\nprintf "%s\\n" "${TEST_UID:-0}"\n')
    write(bin_dir / "python3", common + '''if [ "$1" = -c ]; then exit "${TEST_PYTHON_STATUS:-0}"; fi
if [ "$1" = -m ] && [ "$2" = venv ]; then
  mkdir -p "$3/bin"
  cp "$TEST_VENV_PYTHON" "$3/bin/python"
  chmod +x "$3/bin/python"
  exit 0
fi
if [[ "$1" = */deployment_settings.py ]]; then
  arguments=()
  for argument in "$@"; do
    if [[ "$argument" = /* ]] && command -v cygpath >/dev/null 2>&1; then
      argument="$(cygpath -w "$argument")"
    fi
    arguments+=("$argument")
  done
  exec "$TEST_REAL_PYTHON" "${arguments[@]}"
fi
exit 90
''')
    write(bin_dir / "curl", common + '''[ "${TEST_CURL_FAIL:-0}" = 0 ] || exit 22
output=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then shift; output="$1"; fi
  shift
done
if [ -n "$output" ]; then cp "$TEST_ARCHIVE" "$output"; fi
''')
    for command in ("apt-get", "systemd-tmpfiles", "sleep"):
        write(bin_dir / command, common + "exit 0\n")
    write(bin_dir / "install", common + '''directory=false
if [ "$1" = -d ]; then directory=true; shift; fi
if [ "$1" = -m ]; then shift 2; fi
if [ "$directory" = true ]; then mkdir -p "$@"; else cp "$1" "$2"; fi
''')
    write(bin_dir / "systemctl", common + '[ "${TEST_SYSTEMCTL_FAIL:-0}" = 0 ]\n')
    write(bin_dir / "hostname", '#!/usr/bin/env bash\nprintf "203.0.113.7 \\n"\n')
    fake_python = tmp_path / "venv-python"
    write(fake_python, common + 'exit "${TEST_PIP_FAIL:-0}"\n')
    env["TEST_VENV_PYTHON"] = posix(fake_python)
    return tmp_path, release, env


def stage_bootstrap(shell):
    base, release, env = shell
    text = (ROOT / "scripts" / "bootstrap.sh").read_text(encoding="utf-8")
    text = text.replace("/etc/os-release", posix(release))
    text = text.replace("/tmp/requestwatch-bootstrap", posix(base / "requestwatch-bootstrap"))
    target = base / "bootstrap.sh"
    write(target, text)
    return target


def archive(shell, *, members=None, install_status=0):
    base, _, env = shell
    target = base / "source.tar.gz"
    if members is None:
        members = {
            "RequestWatch-main/pyproject.toml": b"[project]\nname='requestwatch'\n",
            "RequestWatch-main/requestwatch/__init__.py": b"",
            "RequestWatch-main/scripts/install-ubuntu.sh": (
                '#!/usr/bin/env bash\nprintf installed > "$TEST_INSTALL_MARKER"\n'
                f"exit {install_status}\n"
            ).encode(),
        }
    with tarfile.open(target, "w:gz") as bundle:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            if content is None:
                info.type = tarfile.SYMTYPE
                info.linkname = "../../outside"
                bundle.addfile(info)
            else:
                info.size = len(content)
                bundle.addfile(info, io.BytesIO(content))
    env["TEST_ARCHIVE"] = posix(target)
    return target


def run(script, shell):
    base, _, env = shell
    result = subprocess.run(
        [BASH, posix(script)], cwd=base, env=env, capture_output=True,
        encoding="utf-8", errors="replace", timeout=25,
    )
    return result


def log(shell):
    path = shell[0] / "commands.log"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def test_bootstrap_downloads_selected_ref_runs_installer_and_cleans_up(shell):
    archive(shell)
    shell[2]["RW_REF"] = "v0.1.0"
    result = run(stage_bootstrap(shell), shell)
    assert result.returncode == 0, result.stderr
    assert (shell[0] / "installed").read_text() == "installed"
    assert "https://codeload.github.com/10dian-ai/RequestWatch/tar.gz/v0.1.0" in log(shell)
    assert not list(shell[0].glob("requestwatch-bootstrap.*"))


@pytest.mark.parametrize("failure", ["download", "installer"])
def test_bootstrap_propagates_failure_and_cleans_up(shell, failure):
    archive(shell, install_status=7 if failure == "installer" else 0)
    if failure == "download":
        shell[2]["TEST_CURL_FAIL"] = "1"
    result = run(stage_bootstrap(shell), shell)
    assert result.returncode != 0
    assert not list(shell[0].glob("requestwatch-bootstrap.*"))
    if failure == "download":
        assert not (shell[0] / "installed").exists()


@pytest.mark.parametrize("bad_ref", ["../main", "-main", "a//b", "main;id", "main/", "main."])
def test_bootstrap_rejects_invalid_ref_before_download(shell, bad_ref):
    shell[2]["RW_REF"] = bad_ref
    result = run(stage_bootstrap(shell), shell)
    assert result.returncode != 0
    assert "curl " not in log(shell)


@pytest.mark.parametrize("bad_members", [
    {"RequestWatch-main/../outside": b"bad"},
    {"/absolute/outside": b"bad"},
    {"RequestWatch-main/link": None},
    {"one/file": b"1", "two/file": b"2"},
    {"RequestWatch-main/unrelated.txt": b"missing project"},
])
def test_bootstrap_rejects_unsafe_or_incomplete_archive(shell, bad_members):
    archive(shell, members=bad_members)
    result = run(stage_bootstrap(shell), shell)
    assert result.returncode != 0
    assert not (shell[0] / "installed").exists()
    assert not list(shell[0].glob("requestwatch-bootstrap.*"))
    assert not (shell[0] / "outside").exists()


def stage_installer(shell):
    base, release, _ = shell
    source = base / "source"
    script = source / "scripts" / "install-ubuntu.sh"
    target = base / "opt" / "requestwatch"
    etc = base / "etc"
    data = base / "var" / "lib" / "requestwatch"
    runtime = base / "run"
    (runtime / "systemd" / "system").mkdir(parents=True, exist_ok=True)
    (etc / "systemd" / "system").mkdir(parents=True, exist_ok=True)
    text = (ROOT / "scripts" / "install-ubuntu.sh").read_text(encoding="utf-8")
    text = text.replace("/etc/os-release", posix(release))
    text = text.replace("/opt/requestwatch", posix(target))
    text = text.replace("/etc/requestwatch", posix(etc / "requestwatch"))
    text = text.replace("/etc/tmpfiles.d", posix(etc / "tmpfiles.d"))
    text = text.replace("/etc/systemd/system", posix(etc / "systemd" / "system"))
    text = text.replace("/var/lib/requestwatch", posix(data))
    text = text.replace("/run/systemd/system", posix(runtime / "systemd" / "system"))
    write(script, text)
    write(source / "pyproject.toml", "[project]\nname='requestwatch'\n")
    write(source / "scripts" / "deployment_settings.py", (ROOT / "scripts" / "deployment_settings.py").read_text(encoding="utf-8"))
    write(source / "deploy" / "requestwatch.service", "[Service]\n")
    write(source / "deploy" / "requestwatch.env.example", f"RW_HOST=0.0.0.0\nRW_PORT=7030\nRW_DATA_DIR={data.resolve().as_posix()}\n")
    return script, target, etc, data


@pytest.mark.parametrize("script_kind", ["bootstrap", "installer"])
@pytest.mark.parametrize("invalid", ["nonroot", "debian", "oldubuntu", "oldpython"])
def test_deployment_preflight_does_not_mutate_host(shell, script_kind, invalid):
    if invalid == "nonroot":
        shell[2]["TEST_UID"] = "1000"
    elif invalid == "debian":
        write(shell[1], 'ID=debian\nVERSION_ID="12"\n')
    elif invalid == "oldubuntu":
        write(shell[1], 'ID=ubuntu\nVERSION_ID="22.04"\n')
    else:
        shell[2]["TEST_PYTHON_STATUS"] = "1"
    script = stage_bootstrap(shell) if script_kind == "bootstrap" else stage_installer(shell)[0]
    result = run(script, shell)
    assert result.returncode != 0
    assert "apt-get " not in log(shell)
    assert "curl " not in log(shell)
    assert "systemctl " not in log(shell)


def test_install_and_upgrade_preserve_configuration_data_and_token(shell):
    script, target, etc, data = stage_installer(shell)
    result = run(script, shell)
    assert result.returncode == 0, result.stderr
    assert "http://203.0.113.7:7030" in result.stdout
    assert "admin-token" in result.stdout
    assert "systemctl restart requestwatch" in log(shell)
    assert "--upgrade " + posix(target) + "[linux,proxy]" in log(shell)
    env_file = etc / "requestwatch" / "requestwatch.env"
    preserved = env_file.read_text().replace("7030", "7040") + "RW_PROXY=false\n"
    write(env_file, preserved)
    write(data / "admin-token", "keep-this-token\n")
    write(data / "history.sqlite3", "preserve existing records\n")
    result = run(script, shell)
    assert result.returncode == 0, result.stderr
    assert "http://203.0.113.7:7040" in result.stdout
    assert env_file.read_text() == preserved
    assert (data / "admin-token").read_text() == "keep-this-token\n"
    assert (data / "history.sqlite3").read_text() == "preserve existing records\n"


def test_install_reports_startup_failure(shell):
    script, _, _, _ = stage_installer(shell)
    shell[2]["TEST_CURL_FAIL"] = "1"
    result = run(script, shell)
    assert result.returncode != 0
    assert "journalctl" in result.stderr
    assert "Web UI" not in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation requires elevated developer mode")
def test_install_rejects_symlink_target_before_apt(shell):
    script, target, _, _ = stage_installer(shell)
    outside = shell[0] / "outside"
    outside.mkdir()
    target.parent.mkdir(parents=True)
    target.symlink_to(outside, target_is_directory=True)
    result = run(script, shell)
    assert result.returncode != 0
    assert "apt-get " not in log(shell)
    assert not list(outside.iterdir())


@pytest.mark.parametrize("name", ["bootstrap.sh", "install-ubuntu.sh"])
def test_deployment_scripts_have_valid_bash_syntax(name):
    result = subprocess.run([BASH, "-n", posix(ROOT / "scripts" / name)], capture_output=True)
    assert result.returncode == 0, result.stderr.decode(errors="replace")


@pytest.mark.parametrize("host,health_host,display_host", [
    ("127.0.0.1", "127.0.0.1", "127.0.0.1"),
    ("0.0.0.0", "127.0.0.1", "203.0.113.7"),
    ("::", "[::1]", "203.0.113.7"),
    ("2001:db8::2", "[2001:db8::2]", "[2001:db8::2]"),
])
def test_installer_uses_saved_web_address_and_rotated_token_file(shell, host, health_host, display_host):
    script, _, etc, data = stage_installer(shell)
    env_file = etc / "requestwatch" / "requestwatch.env"
    write(env_file, f"RW_HOST=localhost\nRW_PORT=7040\nRW_DATA_DIR={data.resolve().as_posix()}\nRW_TOKEN=old-environment-secret\n")
    saved = json.dumps({"host": host, "port": 7050, "token": "new-web-rotated-secret", "queue_num": 7051})
    write(data / "settings.json", saved)
    write(data / "admin-token", "new-web-rotated-secret\n")
    result = run(script, shell)
    assert result.returncode == 0, result.stderr
    assert f"http://{health_host}:7050/" in log(shell)
    assert f"Web UI：http://{display_host}:7050" in result.stdout
    assert ":7040/" not in log(shell)
    assert "admin-token" in result.stdout and "设置" in result.stdout
    assert "sudoedit" not in result.stdout and "grep" not in result.stdout
    assert "old-environment-secret" not in result.stdout + result.stderr + log(shell)
    assert "new-web-rotated-secret" not in result.stdout + result.stderr + log(shell)
    assert (data / "settings.json").read_text() == saved
    assert (data / "admin-token").read_text() == "new-web-rotated-secret\n"


def test_installer_rejects_saved_shell_text_as_address_without_execution(shell):
    script, _, _, data = stage_installer(shell)
    marker = shell[0] / "injected"
    write(data / "settings.json", json.dumps({"host": f"$(touch {posix(marker)})", "port": 7050}))
    result = run(script, shell)
    assert result.returncode != 0
    assert not marker.exists()
    assert "Web UI：" not in result.stdout
    assert "curl " not in log(shell)


def load_script(name):
    spec = importlib.util.spec_from_file_location("test_" + name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cleanup_uses_initial_saved_and_applied_queue_numbers(tmp_path, monkeypatch):
    cleanup = load_script("cleanup_firewall")
    (tmp_path / "settings.json").write_text(json.dumps({"queue_num": 7050}))
    (tmp_path / "runtime.json").write_text(json.dumps({"active_queue_num": 7040}))
    queues = []
    monkeypatch.setattr(cleanup, "cleanup", queues.append)
    cleanup.cleanup_configured({"RW_QUEUE_NUM": "7030", "RW_DATA_DIR": str(tmp_path)})
    assert queues == [7030, 7050, 7040]
    (tmp_path / "runtime.json").write_text(json.dumps({"active_queue_num": 7050}))
    queues.clear()
    cleanup.cleanup_configured({"RW_QUEUE_NUM": "7030", "RW_DATA_DIR": str(tmp_path)})
    assert queues == [7030, 7050]


@pytest.mark.parametrize("bad_value", [0, 65536, -1, True, 7030.5, "7030; echo injected", []])
def test_cleanup_invalid_saved_queue_does_not_prevent_active_cleanup(tmp_path, monkeypatch, bad_value):
    cleanup = load_script("cleanup_firewall")
    (tmp_path / "settings.json").write_text(json.dumps({"queue_num": bad_value}))
    (tmp_path / "runtime.json").write_text(json.dumps({"active_queue_num": 7040}))
    queues = []
    monkeypatch.setattr(cleanup, "cleanup", queues.append)
    with pytest.raises(RuntimeError, match="settings.json"):
        cleanup.cleanup_configured({"RW_QUEUE_NUM": "7030", "RW_DATA_DIR": str(tmp_path)})
    assert queues == [7030, 7040]


def test_cleanup_continues_after_one_chain_failure(tmp_path, monkeypatch):
    cleanup = load_script("cleanup_firewall")
    (tmp_path / "settings.json").write_text(json.dumps({"queue_num": 7050}))
    (tmp_path / "runtime.json").write_text(json.dumps({"active_queue_num": 7040}))
    queues = []

    def fail_one(queue):
        queues.append(queue)
        if queue == 7030:
            raise RuntimeError("foreign rule")

    monkeypatch.setattr(cleanup, "cleanup", fail_one)
    with pytest.raises(RuntimeError, match="foreign rule"):
        cleanup.cleanup_configured({"RW_QUEUE_NUM": "7030", "RW_DATA_DIR": str(tmp_path)})
    assert queues == [7030, 7050, 7040]


def test_cleanup_never_flushes_unowned_rules_or_other_chain(tmp_path, monkeypatch):
    cleanup = load_script("cleanup_firewall")
    (tmp_path / "settings.json").write_text(json.dumps({"queue_num": 7050}))
    commands = []
    monkeypatch.setattr(cleanup.shutil, "which", lambda name: name if name == "iptables" else None)

    def command(args, **kwargs):
        assert kwargs.get("shell", False) is False
        commands.append(args)
        if "-C" in args:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if "-S" in args:
            chain = args[-1]
            comment = "foreign-rule" if chain == "RWATCH_7030" else "requestwatch-managed-7050"
            return SimpleNamespace(returncode=0, stdout=f"-N {chain}\n-A {chain} -m comment --comment {comment} -j RETURN\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cleanup.subprocess, "run", command)
    with pytest.raises(RuntimeError, match="non-RequestWatch"):
        cleanup.cleanup_configured({"RW_QUEUE_NUM": "7030", "RW_DATA_DIR": str(tmp_path)})
    flushes = [args for args in commands if "-F" in args or "-X" in args]
    assert [args[-2:] for args in flushes] == [["-F", "RWATCH_7050"], ["-X", "RWATCH_7050"]]
    assert all(args[-1] in ("RWATCH_7030", "RWATCH_7050") for args in commands)
