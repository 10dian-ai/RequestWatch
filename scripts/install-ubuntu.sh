#!/usr/bin/env bash
set -euo pipefail
umask 077
fail() { printf 'RequestWatch: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail '请执行 sudo bash scripts/install-ubuntu.sh。'
[ -r /etc/os-release ] || fail '无法读取 /etc/os-release。'
. /etc/os-release
[ "${ID:-}" = ubuntu ] || fail '此安装脚本仅支持 Ubuntu 24.04 或更新版本。'
[[ "${VERSION_ID:-}" =~ ^([0-9]+)\.([0-9]+)$ ]] || fail '无法识别 Ubuntu 版本。'
(( 10#${BASH_REMATCH[1]} > 24 || (10#${BASH_REMATCH[1]} == 24 && 10#${BASH_REMATCH[2]} >= 4) )) || fail '需要 Ubuntu 24.04 或更新版本（Python 3.12+）。'
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' || fail '当前 python3 低于 3.12；请先切换到 Ubuntu 支持的 Python 3.12+。'
fi
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || fail '需要使用 systemd 启动的 Ubuntu 主机。'
project_source="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
project_target=/opt/requestwatch

# Inspect every parent as well as the final target before any privileged writes.
assert_no_symlink() {
  local checked_path="$1"
  [[ "$checked_path" = /* ]] || fail "安装路径必须为绝对路径：$checked_path"
  while [ "$checked_path" != / ]; do
    [ ! -L "$checked_path" ] || fail "拒绝写入符号链接路径：$checked_path"
    checked_path="$(dirname -- "$checked_path")"
  done
}
for checked_path in "$project_target" "$project_target/.venv" \
  /etc/requestwatch/requestwatch.env /var/lib/requestwatch/admin-token \
  /etc/tmpfiles.d/requestwatch.conf /etc/systemd/system/requestwatch.service; do
  assert_no_symlink "$checked_path"
done
if [ -d "$project_target" ]; then
  # A normal virtualenv contains interpreter symlinks. Never archive over it.
  unexpected_link="$(find "$project_target" \( -path "$project_target/.venv" -o -path "$project_target/data" \) -prune -o -type l -print -quit)"
  [ -z "$unexpected_link" ] || fail "部署目录含符号链接，请先人工检查：$unexpected_link"
fi
[ -f "$project_source/pyproject.toml" ] && [ -f "$project_source/deploy/requestwatch.service" ] || fail '源目录缺少 RequestWatch 项目文件。'

export DEBIAN_FRONTEND=noninteractive
# List unrelated services that may need a restart; never restart them automatically.
export NEEDRESTART_MODE=l
apt-get update </dev/null
apt-get install -y python3 python3-venv python3-dev build-essential libnetfilter-queue-dev libpcap-dev iptables iproute2 kmod ca-certificates curl </dev/null
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' || fail '需要 Python 3.12+。'
install -d -m 755 "$project_target" /etc/requestwatch
install -d -m 700 /var/lib/requestwatch
if [ "$project_source" != "$project_target" ]; then
  tar -C "$project_source" --exclude='.git' --exclude='.codex' --exclude='.agents' --exclude='.env' --exclude='.env.*' \
    --exclude='build' --exclude='dist' --exclude='node_modules' --exclude='.venv' --exclude='.proxy-venv' --exclude='data' --exclude='artifacts' \
    --exclude='__pycache__' --exclude='.pytest*' --exclude='*.egg-info' -cf - . | tar -C "$project_target" -xf -
fi
python3 -m venv "$project_target/.venv"
"$project_target/.venv/bin/python" -m pip install --upgrade pip
"$project_target/.venv/bin/python" -m pip install --upgrade "$project_target[linux,proxy]"
if [ ! -f /etc/requestwatch/requestwatch.env ]; then
  install -m 600 "$project_target/deploy/requestwatch.env.example" /etc/requestwatch/requestwatch.env
fi
# Upgrades preserve requestwatch.env and /var/lib/requestwatch, including the token and CA.
# tmpfiles type "f" preserves the existing shared xtables lock inode.
install -d -m 755 /etc/tmpfiles.d
printf '%s\n' 'f /run/xtables.lock 0600 root root -' > /etc/tmpfiles.d/requestwatch.conf
systemd-tmpfiles --create /etc/tmpfiles.d/requestwatch.conf
install -m 644 "$project_target/deploy/requestwatch.service" /etc/systemd/system/requestwatch.service
systemctl daemon-reload
systemctl enable requestwatch
systemctl restart requestwatch

# Saved Web settings override initial environment values. Python parses both files
# as data and emits only the public address/data path; no shell eval or token output.
deployment_values="$(python3 "$project_target/scripts/deployment_settings.py" /etc/requestwatch/requestwatch.env)" || fail '无法读取生效的 Web 配置，请查看上面的设置错误。'
mapfile -t deployment_fields <<< "$deployment_values"
[ "${#deployment_fields[@]}" -eq 3 ] || fail '部署配置读取结果无效。'
web_host="${deployment_fields[0]}"
web_port="${deployment_fields[1]}"
data_path="${deployment_fields[2]}"
case "$web_host" in
  0.0.0.0) check_host=127.0.0.1 ;;
  ::) check_host='[::1]' ;;
  *:*) check_host="[$web_host]" ;;
  *) check_host="$web_host" ;;
esac
ready=false
for attempt in {1..30}; do
  if systemctl is-active --quiet requestwatch && curl --noproxy '*' --fail --silent --max-time 2 "http://$check_host:$web_port/" >/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
[ "$ready" = true ] || fail '服务尚未就绪。请执行 sudo journalctl -u requestwatch -n 80 --no-pager 查看原因。'
printf '\nRequestWatch 已安装，服务已启动。\n'
if [ "$web_host" = 0.0.0.0 ] || [ "$web_host" = :: ]; then
  server_ips="$(hostname -I 2>/dev/null || true)"
  if [ -n "$server_ips" ]; then
    for server_ip in $server_ips; do
      if [[ "$server_ip" = *:* ]]; then server_ip="[$server_ip]"; fi
      printf 'Web UI：http://%s:%s\n' "$server_ip" "$web_port"
    done
  else
    printf 'Web UI：http://<服务器IP>:%s\n' "$web_port"
  fi
else
  printf 'Web UI：http://%s:%s\n' "$check_host" "$web_port"
fi
# Config.prepare synchronizes the effective token (including Web rotations) here.
printf '查看访问令牌：sudo cat %q\n' "$data_path/admin-token"
printf '%s\n' '项目参数、代理监听、访问令牌等均可在 Web UI 的“设置”页面管理。' \
  '设置保存后由服务自动应用；监听地址或端口改变时按页面提示重新访问。' \
  '查看日志：sudo journalctl -u requestwatch -f' \
  '后续升级可再次执行相同的一键安装指令；Web 设置、数据、令牌和 CA 会保留。'
