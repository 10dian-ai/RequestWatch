"""Remove only RequestWatch's tagged mangle rules after the service stops."""
import os
import shutil
import shlex
import subprocess
import sys


def cleanup(queue_number: int):
    if not 1 <= queue_number <= 65535:
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


if __name__ == "__main__":
    try:
        cleanup(int(os.getenv("RW_QUEUE_NUM", "7030")))
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"RequestWatch cleanup: {exc}", file=sys.stderr)
        sys.exit(1)
