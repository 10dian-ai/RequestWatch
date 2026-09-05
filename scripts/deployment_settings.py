"""Read deployment addresses as data; never source an EnvironmentFile as shell code."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re
import shlex
import sys


_FIELDS = {"RW_HOST", "RW_PORT", "RW_DATA_DIR"}


def read_environment(path):
    values = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or key not in _FIELDS:
            continue
        value = value.strip()
        if value.startswith(("'", '"')):
            parts = shlex.split(value, comments=False, posix=True)
            if len(parts) != 1:
                raise ValueError("Invalid quoted deployment environment value")
            value = parts[0]
        values[key] = value
    return values


def deployment_settings(env_file):
    values = read_environment(env_file)
    data_dir = values.get("RW_DATA_DIR") or "/var/lib/requestwatch"
    if not Path(data_dir).is_absolute() or any(ord(c) < 32 for c in data_dir):
        raise ValueError("RW_DATA_DIR must be an absolute path without control characters")
    host = values.get("RW_HOST") or "0.0.0.0"
    port = values.get("RW_PORT") or "7030"
    settings_file = Path(data_dir) / "settings.json"
    try:
        settings = json.loads(settings_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        settings = {}
    if not isinstance(settings, dict):
        raise ValueError("settings.json must contain a JSON object")
    host = settings.get("host", host)
    port = settings.get("port", port)
    if not isinstance(host, str) or not host or len(host) > 253:
        raise ValueError("Invalid Web host in saved settings")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
            raise ValueError("Invalid Web host in saved settings") from None
    if isinstance(port, bool) or not isinstance(port, (str, int)) or not re.fullmatch(r"[0-9]+", str(port)):
        raise ValueError("Invalid Web port in saved settings")
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("Web port must be between 1 and 65535")
    return {"host": host, "port": port, "data_dir": data_dir}


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("Expected the requestwatch.env path")
        result = deployment_settings(sys.argv[1])
        # A fixed UTF-8/LF format is safe for Bash mapfile on every test platform.
        sys.stdout.buffer.write(("\n".join(str(result[key]) for key in ("host", "port", "data_dir")) + "\n").encode("utf-8"))
    except (OSError, ValueError) as exc:
        print(f"RequestWatch deployment settings: {exc}", file=sys.stderr)
        sys.exit(1)
