"""Remove only RequestWatch's tagged mangle rules after the service stops."""
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import sys


def cleanup(queue_number: int):
    if isinstance(queue_number, bool) or not isinstance(queue_number, int) or not 1 <= queue_number <= 65535:
        raise ValueError("Invalid queue number")
    chain = f"RWATCH_{queue_number}"
    comment = f"requestwatch-managed-{queue_number}"
    errors = []
    for binary in ("iptables", "ip6tables"):
        if not shutil.which(binary):
            continue

        def run(*args):
            return subprocess.run([binary, "-w", "2", "-t", "mangle", *args], capture_output=True, text=True, timeout=5)

        for parent in ("INPUT", "OUTPUT", "FORWARD"):
            jump = (parent, "-m", "comment", "--comment", comment, "-j", chain)
            for _ in range(8):
                if run("-C", *jump).returncode:
                    break
                result = run("-D", *jump)
                if result.returncode:
                    errors.append(result.stderr)
                    break
        existing = run("-S", chain)
        if existing.returncode:
            continue
        def owned_rule(line):
            tokens = shlex.split(line)
            return (len(tokens) > 2 and tokens[:2] == ["-A", chain]
                    and "--comment" in tokens
                    and tokens.index("--comment") + 1 < len(tokens)
                    and tokens[tokens.index("--comment") + 1] == comment)

        if any(not owned_rule(line) for line in existing.stdout.splitlines() if line.startswith("-A ")):
            errors.append(f"Refusing to clear non-RequestWatch rules in {chain}")
            continue
        for action in ("-F", "-X"):
            result = run(action, chain)
            if result.returncode:
                errors.append(result.stderr)
    if errors:
        raise RuntimeError("; ".join(errors))


def configured_queue_numbers(environ=None):
    """Read initial, saved, and currently applied queues without interpreting code."""
    environ = os.environ if environ is None else environ
    queues, errors = [], []

    def add(value, source):
        if (isinstance(value, bool) or not isinstance(value, (str, int))
                or not re.fullmatch(r"[0-9]+", str(value)) or not 1 <= int(value) <= 65535):
            errors.append(f"Invalid RequestWatch queue number in {source}")
        elif int(value) not in queues:
            queues.append(int(value))

    add(environ.get("RW_QUEUE_NUM", "7030"), "RW_QUEUE_NUM")
    data_dir = Path(environ.get("RW_DATA_DIR") or "/var/lib/requestwatch")
    for filename, key in (("settings.json", "queue_num"), ("runtime.json", "active_queue_num")):
        try:
            data = json.loads((data_dir / filename).read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object")
            if key in data:
                add(data[key], filename)
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            errors.append(f"Cannot read RequestWatch {filename}")
    return queues, errors


def cleanup_configured(environ=None):
    queues, errors = configured_queue_numbers(environ)
    # An invalid/new configuration must not prevent cleanup of the old active queue.
    for queue_number in queues:
        try:
            cleanup(queue_number)
        except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"Queue {queue_number}: {exc}")
    if errors:
        raise RuntimeError("; ".join(errors))


if __name__ == "__main__":
    try:
        cleanup_configured()
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"RequestWatch cleanup: {exc}", file=sys.stderr)
        sys.exit(1)
