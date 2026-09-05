"""Manage an isolated mitmdump child process without importing mitmproxy."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any


class ProxyProcess:
    def __init__(self, config: Any):
        self.config = config
        self.process: subprocess.Popen | None = None
        self.error: str | None = None
        self._log_file = None

    def _executable(self) -> str | None:
        override = getattr(self.config, "mitmdump", None)
        if override is None:
            override = os.getenv("RW_MITMDUMP")
        if override:
            return shutil.which(override) or (override if Path(override).is_file() else None)
        candidate = Path(sys.executable).parent / ("mitmdump.exe" if os.name == "nt" else "mitmdump")
        return str(candidate) if candidate.is_file() else shutil.which("mitmdump")

    def start(self) -> dict:
        if not self.config.proxy_enabled or (self.process and self.process.poll() is None):
            return self.status()
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None
        self.process = None
        executable = self._executable()
        if not executable:
            self.error = "mitmdump is unavailable. Install mitmproxy or set RW_MITMDUMP to its executable."
            return self.status()
        data_dir = Path(self.config.data_dir).resolve()
        confdir = data_dir / "mitmproxy"
        try:
            confdir.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.name != "nt":
                confdir.chmod(0o700)
            logfile = data_dir / "proxy.log"
            self._log_file = logfile.open("ab", buffering=0)
            if os.name != "nt":
                logfile.chmod(0o600)
            command = [
                executable, "--listen-host", self.config.proxy_host,
                "--listen-port", str(self.config.proxy_port),
                "--set", f"confdir={confdir}", "--set", "connection_strategy=lazy",
                "--set", "flow_detail=0", "--set", "termlog_verbosity=warn",
                "-s", str(Path(__file__).with_name("proxy_addon.py")),
            ]
            proxy_auth = getattr(self.config, "proxy_auth", "")
            if proxy_auth:
                command.extend(["--set", f"proxyauth={proxy_auth}"])
            environment = os.environ.copy()
            api_host = getattr(self.config, "host", "127.0.0.1")
            if api_host == "0.0.0.0":
                api_host = "127.0.0.1"
            elif api_host == "::":
                api_host = "::1"
            if ":" in api_host:
                api_host = f"[{api_host}]"
            environment.update({"RW_API_URL": f"http://{api_host}:{self.config.port}",
                                "RW_TOKEN": self.config.token,
                                "RW_DATA_DIR": str(data_dir)})
            self.process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=self._log_file,
                stderr=subprocess.STDOUT, env=environment,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            self.error = None
        except (OSError, ValueError) as exc:
            self.error = f"Could not start HTTP proxy: {exc}"
            if self._log_file:
                self._log_file.close()
                self._log_file = None
        return self.status()

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self._log_file:
            self._log_file.close()
            self._log_file = None
        self.process = None

    def status(self) -> dict:
        running = self.process is not None and self.process.poll() is None
        if self.process is not None and not running:
            self.error = f"mitmdump exited with code {self.process.returncode}; inspect proxy.log"
        return {
            "enabled": bool(self.config.proxy_enabled), "running": running,
            "host": self.config.proxy_host, "port": self.config.proxy_port,
            "pid": self.process.pid if running else None, "error": self.error,
            "ca_ready": (Path(self.config.data_dir) / "mitmproxy" / "mitmproxy-ca-cert.pem").is_file(),
            "authenticated": bool(getattr(self.config, "proxy_auth", "")),
        }
