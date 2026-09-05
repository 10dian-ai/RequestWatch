#!/usr/bin/env bash
# Install or upgrade RequestWatch from its public GitHub repository.
set -euo pipefail
umask 077

REPO='10dian-ai/RequestWatch'
ref="${RW_REF:-main}"
fail() { printf 'RequestWatch: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail '请使用 sudo bash 运行此脚本。'
[ -r /etc/os-release ] || fail '无法读取 /etc/os-release；需要 Ubuntu 24.04 或更新版本。'
. /etc/os-release
[ "${ID:-}" = ubuntu ] || fail '此脚本仅支持 Ubuntu 24.04 或更新版本。'
[[ "${VERSION_ID:-}" =~ ^([0-9]+)\.([0-9]+)$ ]] || fail '无法识别 Ubuntu 版本。'
(( 10#${BASH_REMATCH[1]} > 24 || (10#${BASH_REMATCH[1]} == 24 && 10#${BASH_REMATCH[2]} >= 4) )) || fail '需要 Ubuntu 24.04 或更新版本（Python 3.12+）。'
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' || fail '当前 python3 低于 3.12；请先切换到 Ubuntu 支持的 Python 3.12+。'
fi
for dependency in curl tar mktemp; do
  command -v "$dependency" >/dev/null 2>&1 || fail "缺少 $dependency。请先执行 sudo apt-get update && sudo apt-get install -y ca-certificates curl tar。"
done
[[ "$ref" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || fail 'RW_REF 只能包含字母、数字、点、下划线、连字符和斜线。'
[[ "$ref" != *..* && "$ref" != *//* && "$ref" != */.* && "$ref" != */ && "$ref" != *. ]] || fail 'RW_REF 不是有效的 Git 分支、标签或提交。'

temporary_dir="$(mktemp -d /tmp/requestwatch-bootstrap.XXXXXXXXXX)"
[[ "$temporary_dir" =~ ^/tmp/requestwatch-bootstrap\.[A-Za-z0-9]{10}$ && -d "$temporary_dir" && ! -L "$temporary_dir" ]] || fail 'mktemp 未返回预期的临时目录。'
cleanup() {
  # Delete only the exact directory created by this invocation, never a ref-derived path.
  if [[ "$temporary_dir" =~ ^/tmp/requestwatch-bootstrap\.[A-Za-z0-9]{10}$ && -d "$temporary_dir" && ! -L "$temporary_dir" && -O "$temporary_dir" ]]; then
    rm -rf -- "$temporary_dir"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf '正在下载 %s（%s）…\n' "$REPO" "$ref"
curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
  --retry 3 --connect-timeout 15 --max-time 180 \
  "https://codeload.github.com/$REPO/tar.gz/$ref" -o "$temporary_dir/source.tar.gz"

# A repository archive must contain ordinary files/directories under one root.
# Reject links and traversal before extraction, even if an archive is unexpected.
tar -tzf "$temporary_dir/source.tar.gz" > "$temporary_dir/members"
tar -tvzf "$temporary_dir/source.tar.gz" > "$temporary_dir/types"
archive_root=''
while IFS= read -r member; do
  [[ -n "$member" && "$member" != /* && "$member" != *\\* && "$member" == */* ]] || fail '归档包含不安全的路径。'
  [[ "/$member/" != */../* && "/$member/" != */./* && "$member" != *//* ]] || fail '归档包含越界路径。'
  member_root="${member%%/*}"
  [[ "$member_root" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail '归档顶层目录无效。'
  if [ -z "$archive_root" ]; then archive_root="$member_root"; fi
  [ "$member_root" = "$archive_root" ] || fail '归档包含多个顶层目录。'
done < "$temporary_dir/members"
[ -n "$archive_root" ] || fail '下载的归档为空。'
while IFS= read -r member_details; do
  [[ "${member_details:0:1}" = '-' || "${member_details:0:1}" = d ]] || fail '归档包含符号链接、硬链接或特殊文件。'
done < "$temporary_dir/types"
mkdir -- "$temporary_dir/source"
tar -xzf "$temporary_dir/source.tar.gz" -C "$temporary_dir/source" \
  --strip-components=1 --no-same-owner --no-same-permissions
project_source="$temporary_dir/source"
[ -f "$project_source/pyproject.toml" ] && [ -f "$project_source/scripts/install-ubuntu.sh" ] && [ -d "$project_source/requestwatch" ] || fail '归档缺少 RequestWatch 项目文件。'
printf '开始安装或升级 RequestWatch…\n'
bash "$project_source/scripts/install-ubuntu.sh"
