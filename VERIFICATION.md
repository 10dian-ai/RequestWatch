# 验证记录

日期：2026-09-05。版本：0.4.1。开发机：Windows，Python 3.14.7；目标部署：Ubuntu 24.04+，Python 3.12+。

## 0.4.1 紧凑界面验证

- 使用用户指定的 tastes-skill（本机 design-taste-frontend），先检查实际运行页面；按数据工作台设定视觉变化 3、动效 1、密度 8。保留现有导航、完整内容与读写行为，重新组织字体、间距与工具栏。
- 同一批演示记录、1440×900、scrollY=0：首条记录从 y523 移到 y269，行高 156px → 72px，首屏完整记录 2 → 8；1366×768 为 6 条，390×844 为 4 条。HTTP 正文从 y536 移到 y263；TCP 独立会话正文从 y974 移到 y480。正文仍为 16px，内容不截短。
- 详情格式、全文搜索、下载合成一排。完整保存与解析成功说明移到正文后；加载、失败和不完整内容仍有明确提示。下载菜单支持键盘展开、Esc 收起、下载后恢复焦点；请求头及连接元数据可以展开。
- ui-body-workspace、ui-body-workspace-live、ui-readable、ui-packet-details 均通过。保留大正文末尾、TCP 双向全文、流式更新、搜索定位、原始字节下载、异常与重试断言。真实 7030 只读测试未创建或修改服务器数据。
- 独立 8044 演示实例完整 ui-smoke 通过：认证、2 MiB 请求/3 MiB 响应全文与下载、HEX、编辑重发、拦截决定、所有设置和移动布局。该轮 full smoke 未配置 TCP 样本，TCP 由前述专用测试及实际页面检查覆盖。
- 实际 7030 在 1440×900、1366×768、390×844 复查流量、HTTP 详情、TCP 列表与正文、设置。无页面横向溢出与浏览器脚本错误；演示说明、下载菜单、完整性说明均可操作。
- JavaScript 语法、git diff --check、0.4.1 wheel 构建与内容核对通过。本轮没有修改采集或存储逻辑，后端基线仍为下方 0.4.0 的 540 项测试。

## 0.4.0 已执行的基础验证

- 完整 Python 回归（开启实际 app/mitmdump 集成）：540 passed、9 skipped、4 subtests passed。两个上游依赖弃用警告；跳过的平台/代理环境限制同下。
- 默认只读：真实 Config 默认 passive_only=True，旧设置升级也默认只读；有旧启用规则仍不调用 NFQUEUE 或安装 iptables 规则。HTTP 代理记录完整保存，但不进入暂停；修改、丢弃、重发接口在只读时拒绝执行。面板可明确关闭只读并应用。
- 被动采集回调保留原始 IP 字节；工作线程按最多 512 条或约 4 MiB 一批写盘，去掉只读路径的 NFQUEUE 去重等待、哈希与每批固定等待。观察队列满时仅记录副本未保存，未截断任何包以提升速度。
- 批次持久化：Store.save_many、TCPStreamStore.ingest_many、Runtime.ingest_packets；覆盖同批乱序/重传/重复 ID、超保留上限、原始字节、单批各数据库一次 COMMIT、并发、失败回滚、冲突以及大 GSO 数据包尾部。暂停路径保留逐包决定语义。另覆盖 SQL 淘汰后异常、COMMIT 被拒绝及提交后清理失败，回滚时旧正文与下载仍完整可读。
- 本机合成保存基准（Windows，同一组 4,000 个 512 B TCP 包、保留上限 1,000）：2.897 秒 → 0.434 秒，约 1,381 → 9,221 包/秒、6.7 倍。原来 8,000 次提交降为 16 次。独立回调微基准为 2.73 倍。这些数据不代表 Ubuntu 实际网卡线速或目标服务器容量。
- 界面按用户参考改为浅蓝宽行事件列表，粗标题、状态图标和明确的详情按钮。正文 16px/600，代码区提供正确中文无衬线回退；默认正文页并列 HTTP 请求体/响应体，TCP 自动读取关联会话双向正文。头信息和连接完整性折叠，原单包和 HEX 保留为次要页签。
- Chromium 新 ui-body-workspace：大正文尾部、双向内容、独立自动/原文切换、流式更新、全文查找/下载、只读隐藏操作、空 GET 正文、抽屉关闭及焦点恢复通过；1440px/390px 无页面横向溢出。原 ui-readable、ui-packet-details 及实际服务的完整 ui-smoke（显式关闭只读以验证可选编辑/重发/拦截）通过。

- 7030 真实演示 API 的只读浏览器验证：HTTP 请求/响应正文与完整 API 逐字一致；点击 31 B TCP 包可直接读取同会话客户端 80,114 B、服务端 31 B 全文，末尾标记可见，下载原始字节完全一致。未注入新数据或调用编辑、重发及设置写接口。CDP 确认中文正文实际字体为 Microsoft YaHei UI Bold，英文为 Cascadia Code SemiBold。
- Python compileall、JavaScript node --check、git diff --check 及 0.4.0 wheel 构建通过；包内版本、完整正文界面、批量保存模块及 AGPL 元数据核对通过。

## 0.3.1 已执行的基础验证

- 冻结全部修改后，完整 Python 回归（RW_RUN_APP_INTEGRATION=1，独立 mitmdump）为 520 passed、9 skipped、4 subtests passed；两个上游依赖弃用警告。代理独立环境另外执行的相关回归 91 passed（包含真实 HTTP/HTTPS；与完整回归有重叠，不相加）。
- 复现并修复列表 240 字摘要被当成完整单包内容、详情加载失败无限等待；浏览器覆盖延迟成功、详情/刷新失败、重试、保留完整快照、完整 HEX 还原文本、末尾标记、TCP 正确方向与反向入口、ACK 无载荷及会话淘汰。
- 真实本地 origin → mitmdump → app/store：普通 SSE、gzip SSE 和 Content-Length 响应提前断开三个场景通过。首段必须在 origin 结束前到达客户端和面板；原文、UTF-8、自动解析及最终字节与客户端一致；突发 20 个网络包不能淘汰仍在接收的 HTTP 记录。
- 正文解码：SSE 不带 charset 的 Latin-1 误解码回归；旧 gzip/Brotli/Zstandard SSE 的自动及 UTF-8 原文从原始字节恢复；半个 UTF-8 字符、压缩尾部、重复 JSON 字段、断线前正文及磁盘失败保留最后成功快照均通过。26 MiB 流式解码内存回归通过。
- 实际 Scapy 序列化包经过被动捕获/NFQUEUE 副本合并、Docker 归属、Runtime、Store、TCP 重组到 HTTP chunked/SSE 解析；1,200 段中文、reasoning_content、乱序重传、超过 100 KB 全文 SHA 一致，数据库只保留 8 条时会话仍完整。此为构造包，不代表 Ubuntu 内核或真实 Docker 路径已经验证。
- 采集停止保存 701 个积压包；负偏移/序号回绕的关闭会话重传不误开新会话；UTF-8 解码器遇到缺口重置，不拼出未完整观测的字符。
- 活动 HTTP 保护：正常无正文长连接通过心跳续约；120 秒失联明确结束活动状态并保留正文；终态不能被迟到心跳复活；待处理决定同步失效；入库确认超时和终态更新重试通过。
- Chromium：新增 ui-packet-details、已有 ui-readable 和完整 ui-smoke 通过。全套保留 2 MiB 请求/3 MiB 响应、全文搜索与下载、HEX、编辑重发、放行/丢弃、所有设置及移动布局。更新后 7030 演示面板的 ui-readable-live 再次验证真实 HTTP/TCP 内容与完整下载。
- Python compileall、JavaScript node --check、git diff --check 及 0.3.1 wheel 构建通过；包内版本、Brotli/Zstandard 运行依赖、模块、界面和 AGPL 元数据核对通过。

本轮主环境跳过 5 项需直接导入 mitmproxy 的代理测试，已由独立代理环境覆盖；其余为 Linux 内核和 Windows 不适用的 POSIX 权限/符号链接场景。目标 Ubuntu 内核、systemd、真实 Docker 网络仍须在实际服务器验证。

## 0.3.0 已执行的基础验证

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

只读真实正文检查：tests/ui-body-workspace-live.cjs，使用已有的隔离演示 HTTP/TCP 样本，不创建或修改数据。

浏览器脚本：tests/ui-body-workspace.cjs（宽行列表与默认双正文）、tests/ui-smoke.cjs（完整功能，包含设置）、tests/ui-settings.cjs（仅设置）、tests/ui-readable.cjs（解析及统计界面隔离验证）、tests/ui-packet-details.cjs（单包加载与会话关联）和 tests/ui-readable-live.cjs（真实演示 API 的 SSE/TCP 验证，TCP 场景通过 RW_UI_READABLE_SESSION_ID 指定预先写入的会话 ID）。需要 playwright-core 和 Chromium；RW_BROWSER_PATH 指定浏览器，RW_UI_URL / RW_UI_TOKEN 指定**演示模式**控制台。脚本创建演示记录、规则及模拟设置，不应用于真实服务器。

## 发布

许可证为 AGPL-3.0-only，源码仓库 https://github.com/10dian-ai/RequestWatch 。一键部署脚本从公开仓库下载源码，重复运行会保留配置、数据库、完整正文和 CA。
