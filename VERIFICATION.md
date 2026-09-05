# 验证记录

日期：2026-09-05。版本：0.3.0。开发机：Windows，Python 3.14.7；目标部署：Ubuntu 24.04+，Python 3.12+。

## 0.3.0 本次验证

- 完整 Python 回归（RW_RUN_APP_INTEGRATION=1，使用独立 mitmdump）：470 passed，8 skipped，4 subtests passed。两个上游 Starlette 弃用警告；跳过项的平台限制同下。
- 累计统计：保留上限淘汰后累计数继续增长，同一请求响应更新不重复计数，重启保存计数，旧数据库迁移及并发写入通过。
- 可读解析：36 项测试，覆盖 HTTP chunked、keep-alive、gzip/deflate、跨块 UTF-8、SSE 中文增量及换行合并、超大事件完整保留；超过 10 MiB 的压缩解码输出峰值 Python 内存低于 4 MiB。二进制、缺包及不明确的报文边界会提示解析限制。
- 可读 API：认证、完整内容及下载、缓存归属和版本校验通过；TCP 解析与导出使用同一快照，缺口、冲突、分片或截断数据不会被当成可靠完整内容。
- Chromium 原有 ui-smoke 全通过：完整 2 MiB 请求/3 MiB 响应、全文搜索与下载、HEX、大正文编辑重发、拦截放行/丢弃、项目设置及移动布局。
- Chromium ui-readable：保留 10,000 条时累计数继续增长、暂停刷新、自动/原文切换、草稿和滚动位置保留、解析失败回退及方向标签通过。
- Chromium ui-readable-live：向真实演示 API 注入 SSE 数据，验证累计 +1、响应更新不重复计数、中文合并及原文完整下载；真实 TCP 存储中的 441 字节分块数据验证中文解析、端点方向提示、全文/原文下载及移动布局。测试数据为人工构造，未接入目标服务器流量。
- Python compileall、JavaScript node --check 通过；0.3.0 wheel 构建并核对解析模块、界面及 AGPL 元数据通过。

## 0.2.0 已执行的基础验证

- 完整 Python 回归（开启真实 app 集成）：425 passed，8 skipped，4 subtests passed。
- 最后监听预检/回退修复后，26 项定向回归通过，覆盖新增IPv4/IPv6冲突测试、真实配置回退、主程序代理链路和全文接口。
- 独立 mitmproxy 环境：32 项通过，含真实 HTTP/HTTPS、信任测试 CA、暂停/改写/丢弃，以及 1,260,017 字节请求与完整响应落盘、哈希和原样重发比对。
- 主程序全链路：真实 FastAPI + mitmdump + 本地 origin；2 MiB 请求末尾关键词触发暂停，改为 3 MiB 后完整放行、全文下载、响应下载及原样/编辑重发均通过。
- TCP 会话：IPv4/IPv6 双方向、乱序、重传、冲突、缺口、序号回绕、连接复用、重启与保留；2.3 MiB 字节哈希及跨包/跨读取块尾部搜索通过。慢盘搜索/导出不会占锁阻塞采集，导出保持同一版本快照。
- Web 设置：严格白名单、输入校验、秘密字段脱敏、0600/原子替换、失败保留旧文件和并发更新验证。真实临时 CLI 通过面板 API 改端口、轮换令牌并优雅重启，新的保留数量、等待数、规则默认超时和会话超时生效；占用端口拒绝重启且旧面板可访问；另外验证全部IPv4/IPv6地址预检，以及预检后端口被抢占时自动恢复旧端口/令牌。
- Chromium：完整 2 MiB 请求/3 MiB 响应查看、末尾搜索、完整下载、HEX 末页、大正文编辑重发、草稿/滚动位置保留、拦截操作通过；80 KiB TCP 双向全文、搜索、下载、HEX 末页通过。
- Chromium 项目设置：所有运行字段保存、待应用状态、演示应用、未保存草稿、令牌/密码不回显、明确清除认证、新规则默认超时通过。1440px 桌面与390px手机无页面横向溢出。
- 安装器/清理命令桩：41 passed，1 skipped。覆盖首次安装、升级保留、Web 设置覆盖健康检查/访问地址、IPv4/IPv6、下载/服务失败、归档检查；停止时按环境/已保存/当前运行队列做精确自有规则清理。
- 浏览器回退UI另有4分支隔离验证：恢复原令牌、正常令牌轮换、跨地址原链接以及已回退状态提示。
- Python compileall、JavaScript node --check、Ubuntu安装脚本 bash -n 通过；0.2.0 wheel构建并核对最新模块、界面和AGPL元数据通过。

主环境跳过的4项代理相关测试已在独立代理环境执行；其余跳过为Linux真实内核集成、Windows不支持的POSIX权限/符号链接测试。两个警告来自上游Starlette测试依赖弃用提示。

## 未在当前机器执行

- Ubuntu 内核 NFQUEUE 实际拦截、systemd 运行。
- Docker bridge、rootless、host 网络及目标容器真实流量归属。
- 实际Ubuntu服务器 apt/systemd 部署和目标应用CA安装。

项目提供 tests/test_linux_integration.py，需在Ubuntu以root显式设置 RW_RUN_LINUX_INTEGRATION=1 运行。该测试在全新的 unshare 网络命名空间内操作，先校验隔离状态，仅使用lo，不修改宿主机防火墙。

## 复验

```bash
.venv/bin/python -m pip install '.[test,linux,proxy]'
RW_RUN_APP_INTEGRATION=1 RW_RUN_PROXY_INTEGRATION=1 .venv/bin/python -m pytest -q
sudo env RW_RUN_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_linux_integration.py -q
```

浏览器脚本：tests/ui-smoke.cjs（完整功能，包含设置）、tests/ui-settings.cjs（仅设置）、tests/ui-readable.cjs（解析及统计界面隔离验证）和 tests/ui-readable-live.cjs（真实演示 API 的 SSE/TCP 验证，TCP 场景通过 RW_UI_READABLE_SESSION_ID 指定预先写入的会话 ID）。需要 playwright-core 和 Chromium；RW_BROWSER_PATH 指定浏览器，RW_UI_URL / RW_UI_TOKEN 指定**演示模式**控制台。脚本创建演示记录、规则及模拟设置，不应用于真实服务器。

## 发布

许可证为 AGPL-3.0-only，源码仓库 https://github.com/10dian-ai/RequestWatch 。一键部署脚本从公开仓库下载源码，重复运行会保留配置、数据库、完整正文和 CA。
