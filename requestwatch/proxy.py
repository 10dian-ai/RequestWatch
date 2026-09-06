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
        self.reverse_process: subprocess.Popen | None = None
        self.reverse_error: str | None = None
        self._reverse_log_file = None

    def _executable(self) -> str | None:
        override = getattr(self.config, "mitmdump", None)
        if override is None:
            override = os.getenv("RW_MITMDUMP")
        if override:
            return shutil.which(override) or (override if Path(override).is_file() else None)
        candidate = Path(sys.executable).parent / ("mitmdump.exe" if os.name == "nt" else "mitmdump")
        return str(candidate) if candidate.is_file() else shutil.which("mitmdump")

    def _reverse_enabled(self) -> bool:
        return (bool(self.config.proxy_enabled)
                and getattr(self.config, "inspection_profile", "network") == "newapi"
                and bool(getattr(self.config, "newapi_upstream", "")))

    def start(self) -> dict:
        if not self.config.proxy_enabled:
            return self.status()
        executable = self._executable()
        if not executable:
            self.error = "mitmdump is unavailable. Install mitmproxy or set RW_MITMDUMP to its executable."
            return self.status()
        self._start_child(executable, reverse=False)
        if self._reverse_enabled():
            self._start_child(executable, reverse=True)
        return self.status()

    def _start_child(self, executable: str, *, reverse: bool) -> None:
        process_name = "reverse_process" if reverse else "process"
        error_name = "reverse_error" if reverse else "error"
        log_name = "_reverse_log_file" if reverse else "_log_file"
        process = getattr(self, process_name)
        if process is not None and process.poll() is None:
            return
        previous_log = getattr(self, log_name)
        if previous_log is not None:
            previous_log.close()
            setattr(self, log_name, None)
        setattr(self, process_name, None)
        data_dir = Path(self.config.data_dir).resolve()
        # Separate directories prevent two first-start processes racing to
        # generate the same CA or inheriting each other's authentication config.
        confdir = data_dir / ("mitmproxy-reverse" if reverse else "mitmproxy")
        try:
            confdir.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.name != "nt":
                confdir.chmod(0o700)
            logfile = data_dir / ("proxy-reverse.log" if reverse else "proxy.log")
            output = logfile.open("ab", buffering=0)
            setattr(self, log_name, output)
            if os.name != "nt":
                logfile.chmod(0o600)
            port = getattr(self.config, "newapi_reverse_port", 8081) if reverse else self.config.proxy_port
            command = [
                executable, "--listen-host", self.config.proxy_host,
                "--listen-port", str(port),
                "--set", f"confdir={confdir}", "--set", "connection_strategy=lazy",
                "--set", "flow_detail=0", "--set", "termlog_verbosity=warn",
                "-s", str(Path(__file__).with_name("proxy_addon.py")),
            ]
            if reverse:
                command.extend(["--mode", "reverse:" + self.config.newapi_upstream,
                                "--set", "keep_host_header=true", "--set", "proxyauth="])
            else:
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
                                "RW_DATA_DIR": str(data_dir),
                                "RW_CAPTURE_LEG": "client" if reverse else "upstream",
                                "RW_INSPECTION_PROFILE": getattr(self.config, "inspection_profile", "network")})
            process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.STDOUT, env=environment,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            setattr(self, process_name, process)
            setattr(self, error_name, None)
        except (OSError, ValueError) as exc:
            setattr(self, error_name, f"Could not start HTTP proxy: {exc}")
            output = getattr(self, log_name)
            if output is not None:
                output.close()
                setattr(self, log_name, None)

    def stop(self) -> None:
        for process_name, log_name in (("reverse_process", "_reverse_log_file"), ("process", "_log_file")):
            process = getattr(self, process_name)
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            output = getattr(self, log_name)
            if output is not None:
                output.close()
                setattr(self, log_name, None)
            setattr(self, process_name, None)

    def status(self) -> dict:
        running = self.process is not None and self.process.poll() is None
        reverse_running = self.reverse_process is not None and self.reverse_process.poll() is None
        if self.process is not None and not running:
            self.error = f"mitmdump exited with code {self.process.returncode}; inspect proxy.log"
        if self.reverse_process is not None and not reverse_running:
            self.reverse_error = f"mitmdump exited with code {self.reverse_process.returncode}; inspect proxy-reverse.log"
        reverse_enabled = self._reverse_enabled()
        error = self.error or (self.reverse_error if reverse_enabled else None)
        return {
            "enabled": bool(self.config.proxy_enabled), "running": running,
            "host": self.config.proxy_host, "port": self.config.proxy_port,
            "pid": self.process.pid if running else None, "error": error,
            "ca_ready": (Path(self.config.data_dir) / "mitmproxy" / "mitmproxy-ca-cert.pem").is_file(),
            "authenticated": bool(getattr(self.config, "proxy_auth", "")),
            "reverse": {
                "enabled": reverse_enabled, "running": reverse_running,
                "host": self.config.proxy_host, "port": getattr(self.config, "newapi_reverse_port", 8081),
                "upstream": getattr(self.config, "newapi_upstream", ""),
                "pid": self.reverse_process.pid if reverse_running else None,
                "error": self.reverse_error, "authenticated": False,
            },
        }
