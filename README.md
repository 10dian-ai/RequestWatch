# RequestWatch

[源码仓库](https://github.com/10dian-ai/RequestWatch) · [AGPL-3.0-only](LICENSE) · [验证记录](VERIFICATION.md)

部署在 Ubuntu 的本机与 Docker 网络调试工具。**Web UI 默认端口 7030**，HTTP/HTTPS 代理默认端口 8080。

默认以**只读观察**方式运行：捕获网络副本、搜索完整内容、按容器筛选，不暂停、修改或重发真实流量。列表采用紧凑浅蓝布局，桌面记录行高 72px；点击「查看详情」直接并列展示 HTTP 请求体和响应体，TCP 包直接展示关联会话的双向正文。正文使用大字号深色文字，支持全文查找和下载。

## 一键部署（Ubuntu 24.04+）

在 Ubuntu 服务器执行：

```bash
curl -fsSL https://raw.githubusercontent.com/10dian-ai/RequestWatch/main/scripts/bootstrap.sh | sudo bash
```

安装完成后访问 **http://服务器IP:7030**，使用以下命令查看登录令牌：

```bash
sudo cat /var/lib/requestwatch/admin-token
```

脚本下载本仓库源码，安装运行依赖，配置 systemd 并启动服务；重复执行可更新程序，保留已有配置、数据库和 CA。默认代理只监听本机8080，安装后在面板「项目设置」调整，无需逐项编辑 SSH 配置；Docker容器接入方法见后文。需要服务器能访问 GitHub 和 Ubuntu/PyPI 软件源。

如需固定版本，可把安装命令末尾改为 `sudo env RW_REF=<分支名或版本标签或commit> bash`。这固定下载的项目源码版本；引导脚本本身仍来自命令中指定的 main。

## 当前能力

| 能力 | TCP / UDP 原始包 | HTTP / HTTPS 代理 |
| --- | --- | --- |
| 捕获与查看 | IPv4 / IPv6 TCP、UDP；TCP 按连接和方向重组，全文及 HEX | 完整方法、URL、请求头、请求/响应正文、状态码 |
| 内容搜索 | 原始包内文本；TCP 会话全文支持跨包匹配 | URL、头、完整解码正文，包括大正文末尾 |
| 容器筛选 | 按源/目标容器 IP 归属 | 按连接到代理的客户端 IP 归属 |
| 规则暂停 | 容器、目标 IP/CIDR、端口、包内关键词 | 容器、目标主机、端口、请求关键词 |
| 编辑后放行 | TCP 等长载荷修改；UDP 更新长度/校验和 | 支持修改方法、URL、重复请求头和正文 |
| 丢弃 | 丢弃当前包；发送方可能重传 | 返回本地 499，不向上游发送该请求 |
| 重发 | 使用宿主机新 TCP 连接或新 UDP 数据报 | 使用宿主机新 HTTP 请求，保留原始二进制正文 |

以上暂停、编辑、丢弃、重发能力默认关闭。只有在「项目设置」明确关闭「只读观察」并应用后才可使用。规则内条件全部满足才暂停，多条规则按创建顺序命中第一条。默认等待 30 秒，可设为 5–120 秒，超时放行原始内容。原始包暂停与代理暂停是两个独立接入路径。

## Ubuntu 安装

建议 Ubuntu 24.04 LTS 或更新版本，Python 3.12+，root 权限；支持 Docker Engine。将整个项目上传到服务器，然后在项目根目录执行：

```bash
sudo bash scripts/install-ubuntu.sh
sudo systemctl status requestwatch
sudo cat /var/lib/requestwatch/admin-token
```

访问 **http://服务器IP:7030**，输入上面的令牌。安装脚本默认 Web UI 监听 0.0.0.0:7030，防火墙应允许你的管理设备访问。原始抓包引擎和 HTTP 代理的实际状态会显示在页面中。

脚本安装到 /opt/requestwatch，创建 Python 虚拟环境和 systemd 服务。数据、CA 私钥及令牌存放于 /var/lib/requestwatch。现有配置和数据在重新安装时保留。

打开面板导航中的 **「项目设置」**，修改后点击 **「保存设置」→「重启服务并应用」**。面板会列出待应用字段，应用前检查监听地址/端口；监听地址变更后给出新的访问链接；若新配置启动失败，会自动恢复上次可用设置，回到原地址和原令牌。

可调整：Web 监听地址/端口、管理令牌、只读观察模式、抓包开关、网卡、NFQUEUE 编号、额外保护端口、等待数量、规则默认超时、代理开关/地址/端口/认证、mitmdump 路径、记录保留数量和 TCP 会话空闲时间。访问令牌支持在面板生成与轮换，代理认证支持明确清除；查询接口不返回这些秘密的明文。

设置保存在 `/var/lib/requestwatch/settings.json`，覆盖环境变量和命令行的初始值，升级保留。点击应用后程序先停止现有网络引擎并重载配置；当前连接可能中断，待处理记录在重启后失效。通过一键安装或 `requestwatch` / `python -m requestwatch` 启动时均支持面板重启。演示设置独立保存且只模拟应用。

安装程序的目录、数据根目录和 systemd 系统约束属于部署布局，面板只读显示数据路径；不会在修改运行参数时搬迁捕获数据。目标程序的代理设置与 CA 信任须在目标运行环境配置，接入指南提供可复制内容和证书下载。

默认排除 22、7030、8080 的双向网络流量，防止 SSH 和管理/代理流量进入原始抓包反馈循环。**SSH 使用其他端口时，请先在面板「项目设置 → 额外保护端口」中追加该端口。** 保护范围不阻止你在 HTTP 代理内调试其他应用的 HTTPS 请求。

### 手动安装 / 开发

```bash
sudo apt-get install python3-venv python3-dev build-essential libnetfilter-queue-dev libpcap-dev iptables
python3 -m venv .venv
.venv/bin/python -m pip install '.[linux,proxy,test]'
sudo .venv/bin/python -m requestwatch --host 0.0.0.0 --port 7030
```

使用 --no-capture 可仅运行代理及控制台；--no-proxy 可仅运行原始抓包。Windows/macOS 不能运行本项目的 Linux 内核拦截引擎，但可以运行操作台和 HTTP 代理。

### 本地界面演示

```bash
python -m venv .venv
# Linux：.venv/bin/python；Windows：.venv\Scripts\python.exe
.venv/bin/python -m pip install '.[test]'
.venv/bin/python -m requestwatch --demo --port 7030
```

演示令牌位于 data/demo/admin-token。页面明确显示演示标识。在演示设置中关闭只读观察并应用，创建一条规则后，使用「生成匹配演示请求」体验暂停、编辑、放行、丢弃；演示重发只创建模拟记录。演示数据库与真实数据库分开。

## 配置 HTTP / HTTPS

### 本机程序

代理默认只监听 127.0.0.1:8080。本机应用配置：

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
# 某些客户端只识别小写变量。
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"
curl --proxy http://127.0.0.1:8080 http://example.com/
```

HTTP_PROXY / HTTPS_PROXY 是否生效取决于目标应用是否支持它们。

在 Web UI 的「接入指南」下载 CA 公共证书并安装到**目标程序实际使用的信任库**，然后验证 HTTPS。也可以从服务器获取：

```bash
sudo cp /var/lib/requestwatch/mitmproxy/mitmproxy-ca-cert.pem /tmp/requestwatch-ca.crt
curl --proxy http://127.0.0.1:8080 --cacert /tmp/requestwatch-ca.crt https://example.com/
```

不要分发 mitmproxy-ca.pem，它包含 CA 私钥。下载接口仅提供 mitmproxy-ca-cert.pem 公共证书。项目不自动修改系统信任库，也不关闭上游 TLS 校验。

### Docker 容器

1. 在面板「项目设置 → HTTP 代理」把监听地址设为可达的宿主机 bridge 地址，或 0.0.0.0。
2. 点击「保存设置」和「重启服务并应用」。
3. 给目标容器配置代理和证书。以下片段合并到**目标应用**的 Compose 文件中：

```yaml
services:
  app:
    # image: 你的应用镜像
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      HTTP_PROXY: http://host.docker.internal:8080
      HTTPS_PROXY: http://host.docker.internal:8080
      http_proxy: http://host.docker.internal:8080
      https_proxy: http://host.docker.internal:8080
      NO_PROXY: localhost,127.0.0.1
      # 下面变量仅适用于对应应用，按实际运行时选择。
      REQUESTS_CA_BUNDLE: /certs/requestwatch-ca.crt
      NODE_EXTRA_CA_CERTS: /certs/requestwatch-ca.crt
    volumes:
      - ./requestwatch-ca.crt:/certs/requestwatch-ca.crt:ro
```

此片段只解决接入配置，不会自动把证书安装到 Java、浏览器等独立信任库。需要镜像级信任时，参阅 [Docker 官方 CA 文档](https://docs.docker.com/engine/network/ca-certs/)。

代理可被其他设备访问时，在面板填写代理认证 `user:password` 并限制防火墙来源。目标客户端代理 URL 需包含对应用户名/密码，特殊字符需 URL 编码。7030 的管理令牌与代理认证是两套独立凭据。

## 操作流程

1. 打开 7030 页面登录，确认抓包/代理引擎状态。
2. 在「网络流量」叠加关键词、协议、容器和状态筛选；点击记录查看请求、响应、概要或 HEX。
3. 在「拦截规则」创建窄范围规则。原始包目标地址支持 IP/CIDR；HTTP 支持目标主机文字匹配。
4. 命中规则后打开「拦截队列」，选择记录。直接放行或编辑后放行；丢弃则终止对应包/HTTP 请求。
5. 已处理记录可以「重发请求」。HTTP 重发支持编辑完整请求；TCP/UDP 重发只发送所选应用载荷。
6. 请求/响应页自动加载完整正文，支持下载原始字节和重建的完整 HTTP 消息；HEX 可分页并跳转至任意位置。JSON 导出是元数据与预览，完整正文请用正文或 HTTP 下载。
7. 打开「TCP 会话」按容器和全文关键词筛选，分别查看客户端→服务端与服务端→客户端内容；原始 TCP 包也可跳转到所属会话。
8. 页面每 2 秒刷新，可暂停刷新；刷新不会覆盖尚未提交的编辑草稿。

响应正文支持搜索，但**请求发送前的暂停规则不能匹配未来尚未收到的响应**。TCP 会话搜索会跨包匹配，原始包暂停规则仍逐包匹配；通用 TCP 连接没有统一的“请求结束”定义。需要在完整 HTTP 请求发送前编辑时，使用 HTTP/HTTPS 代理路径。

### 统计与可读内容

首页「累计捕获」持续增加，「当前保留」受设置中的保留上限约束。达到默认 10000 条后，新记录替换旧记录，保留数会保持不变；最近捕获时间和累计数用于判断是否仍有流量。更新旧版本时以现存记录作为累计基线，先前已淘汰的数量无法追溯，页面会明确说明。

HTTP 正文与 TCP 会话默认使用「自动解析」：识别 HTTP/1 分块、gzip/deflate、JSON 与 SSE 流式事件，将常见聊天增量拼接成正文，单独显示思考字段，同时保留完整事件明细。换行与 Unicode 转义会被解码，不再把分块长度当正文显示。可以切回原文、HEX，并分别下载解析文本或原始字节。

解析是对已捕获内容的辅助视图，原始数据不会被替换。没有 HTTP 头时仅在结构匹配时推断分块格式并标记不完整；缺口、截断或重传冲突不跨片段拼接；TLS 密文不会被伪装成明文。超过单事件 JSON 解析预算时完整保留事件文本并提示，不截断文件。没有配对请求上下文的 HEAD/CONNECT 响应边界无法保证判断，需以原文或 HTTP 代理记录核对。

### 单包、完整会话与流式响应

网络包列表只提供摘要。打开详情后会重新读取该包的全部已保存字节；失败时显示原因与重试入口，不会把 240 字摘要标为全文。一个 TCP 包只包含连接中的一个片段，默认正文页直接载入同一连接的双向重组内容；「单包载荷」与 HEX 保留原始包的查看方式。没有载荷的 ACK、握手包以及已淘汰的会话会明确提示。

HTTP/HTTPS 代理的响应边接收边转发，并约每秒保存一次已收到的正文快照，SSE 不用等连接关闭后才显示。SSE 固定按 UTF-8 解码，支持 gzip、deflate、Brotli、Zstandard 等压缩；旧版本错误解码的 SSE 可从仍保留的原始正文重新生成文本。流式正文进行中会标记未结束，中断时保留已收到的部分，不将其标成完整响应。

尚未收完响应的 HTTP 记录不会被包数量上限提前淘汰，因此大量同时进行的响应可临时使保留数超过上限。代理每 10 秒确认活动连接；连续 120 秒未确认会标为采集失联、完整性未知，保留已有正文并停止永久占用活动名额。代理重启后无法继续原连接。服务停止时先停止抓包，再保存观察队列里已有的包。

只读采集不安装 NFQUEUE/iptables 拦截规则，也不执行暂停规则。抓取副本按最多 512 条或约 4 MiB 一批写入数据库和 TCP 文件，完整保留原字节；批次复用文件句柄，避免每包重复提交。副本保存跟不上时会明确显示未保存副本计数与队列状态；该计数不代表真实连接的网络包因此被丢弃，也不涵盖内核丢包。受抓包开始时间、网卡可见范围、保护端口排除、IP 分片、TLS 加密和存储保留上限影响，系统不能补回从未捕获或已淘汰的字节。TCP 原始导出按顺序包含已观测范围，缺口不补字节；文本解码不会把缺口两边残余字节拼成同一个字符。

### 完整内容如何保存

- HTTP/HTTPS 原始正文和解码全文按内容哈希保存到 `body_blobs/`，取消旧版每项 1 MiB 的截断。数据库只保留 64 KiB 预览，详情页自动加载全文，编辑和重发使用完整文件；二进制上传、压缩正文保留原始字节。
- HTTP 下载包含起始行、全部已记录请求头和正文，重建为 HTTP/1.1 形式并修正长度/分块头，尾部头合并为头字段；HTTP/2 帧、原始分块边界不属于该导出。原协议版本和尾部头仍保存在元数据中。
- TCP 会话按序列号重组双向内容，处理乱序和重传；相同序号内容冲突时保留先观察到的字节并显示冲突。只有观察到双向 SYN/FIN 且无缺口、截断或冲突时标记连接完整。这不代表目标程序确认收到了所有内容。
- 若抓取从连接中途开始、丢包或 IP 分片无法重组，页面明确显示不完整。TCP 导出仅包含观察到的字节，按序号排列，缺口省略且在详情列明，不能把省略后的连续文本当作实际线上连续内容。加密会话仍显示密文。
- 旧版本已截掉的内容无法补回，需要重新抓取。磁盘写入失败、传输中断不会标记为完整。

## 范围和实际限制

- HTTPS 解密需要目标客户端经过代理且信任 CA。证书固定、独立信任库、忽略代理的程序需要另行适配。非 HTTP 的 TLS/QUIC 数据仍是密文。
- 这是单机调试工具，没有集群、用户角色、流量审计服务或线速采集承诺。原始包使用有界用户态缓冲，页面会报告被动采集丢包计数。
- 启用原始包规则时，符合协议且不在保护端口中的包先进入 NFQUEUE，再由用户态精确匹配。高负载会增加延迟；内核队列满可能丢包。--queue-bypass 只解决没有监听进程的情况，不保证内核队列满时放行。
- 系统规则只新增本项目命名的 mangle 链及带注释的跳转，不清空 Docker、防火墙规则或修改默认策略。关闭原始包规则/正常停止服务会移除跳转并处理等待包；systemd 退出后还执行定向清理。
- Python NetfilterQueue 绑定对较大的包可能截断。截断包、IP 分片和不适合修改的特殊 IPv6 头禁止编辑。TCP 只能等长修改，并用有界 5 分钟缓存处理重传；超长连接不保证无限期重传一致性。
- TCP 原始包丢弃不是取消应用请求；发送方可能再次重传。TCP 载荷重发不是原连接恢复，不复用原序列号、TLS 握手或容器身份。新连接的结果取决于应用协议；UDP 也可能因认证或状态要求不能独立重发。
- 抓取宿主机可见的网络接口并动态识别新增接口。容器内部 loopback 不经过宿主机网络；某些 bridge 路径是否经过 Netfilter 依赖 br_netfilter 配置。此类路径不承诺全部可见。
- 容器归属基于 Docker 公共网络 IP。host 网络、共享 IP、rootless Docker、NAT 后地址及跨命名空间路径可能显示「未知来源」；不会伪造精确归属。Docker socket 查询只读，但进程按用户选择以 root 运行。
- HTTP 正文无固定 1 MiB 保存上限，实际受可用磁盘与内存限制。代理需要缓冲完整 HTTP 消息用于修改，浏览器全文视图也会占用内存；响应需接收结束才有完整正文。WebSocket 消息、无限 SSE 流未单独解析。
- 默认保留最近 10000 条记录和最近 10000 个 TCP 会话；会话 5 分钟无包后再次出现会另起会话。正文文件在所属记录淘汰后延迟至少 10 分钟清理；TCP 会话文件随会话淘汰。数量上限并非磁盘容量上限，长会话和大正文仍会占用大量空间。SQLite 复用已分配空间，数据保存在 /var/lib/requestwatch。

## 配置项

日常配置使用 Web「项目设置」。下表列出初次启动的环境默认值；面板保存的设置优先。

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| RW_HOST | 127.0.0.1（安装服务为0.0.0.0） | Web监听地址 |
| RW_PORT | 7030 | Web端口 |
| RW_DATA_DIR | data（安装服务为/var/lib/requestwatch） | 持久数据 |
| RW_TOKEN | 自动生成并保存 | Web/API令牌，至少16字符 |
| RW_CAPTURE | true | 启用Linux抓包 |
| RW_PASSIVE_ONLY | true | 只读观察，不暂停、改写或重发；不安装原始包拦截规则 |
| RW_INTERFACES | any | 全部接口，或逗号分隔的接口名 |
| RW_QUEUE_NUM | 7030 | 独占NFQUEUE编号 |
| RW_PROTECTED_PORTS | 22 | 排除端口，自动追加Web/代理端口 |
| RW_MAX_RECORDS | 10000 | 记录及TCP会话各自保留上限，至少100 |
| RW_PENDING_LIMIT | 128 | 等待拦截决定的数量上限 |
| RW_DEFAULT_TIMEOUT | 30 | 新规则默认等待秒数 |
| RW_TCP_IDLE_TIMEOUT | 300 | 会话无包后再次出现时另起会话的秒数 |
| RW_PROXY | true | 启用HTTP/HTTPS代理 |
| RW_PROXY_HOST | 127.0.0.1 | 代理监听地址 |
| RW_PROXY_PORT | 8080 | 代理端口 |
| RW_PROXY_AUTH | 空 | 可选代理user:password |
| RW_MITMDUMP | 自动探测 | 指定mitmdump可执行文件 |

同一服务器只运行一个使用同一数据目录/队列编号的实例。反向代理 Web UI 时，保留 Authorization 请求头，并在反向代理处配置 HTTPS。

## 验证与排障

```bash
.venv/bin/python -m pip install '.[test]'
.venv/bin/python -m pytest -q
# 真实mitmdump回环集成（需要proxy依赖，不访问外网）：
RW_RUN_PROXY_INTEGRATION=1 .venv/bin/python -m pytest tests/test_proxy.py -q
```

Ubuntu 的真实内核拦截验证在全新的网络命名空间中执行，不接入宿主机接口：

```bash
sudo env RW_RUN_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_linux_integration.py -q
```

测试覆盖搜索和容器双向筛选、拦截单次决定、超时/容量上限、数据保留、访问令牌、代理改写与丢弃、包校验和、TCP重传、HTTP/TCP/UDP重放。Linux 内核路径需在 Ubuntu 上运行单独的隔离命名空间测试；默认测试不会修改宿主机防火墙。

查看状态和实际服务日志：

```bash
sudo journalctl -u requestwatch --since '10 minutes ago'
sudo tail -n 60 /var/lib/requestwatch/proxy.log
sudo iptables -t mangle -S
sudo ip6tables -t mangle -S
```

停止后如需手动清理本项目遗留规则：

```bash
sudo systemctl stop requestwatch
sudo env RW_QUEUE_NUM=7030 python3 /opt/requestwatch/scripts/cleanup_firewall.py
```

不要在服务运行时执行清理，也不要用 iptables -F 清空系统规则。

## 结构

- requestwatch/app.py：7030 Web/API、认证、控制接口
- requestwatch/runtime.py / store.py / rules.py：拦截生命周期、SQLite、组合规则
- requestwatch/network.py：被动捕获与 NFQUEUE
- requestwatch/body_store.py：完整HTTP正文文件
- requestwatch/stream_decode.py / readable_cache.py：HTTP/JSON/SSE 可读解析与临时快照
- requestwatch/settings.py：面板设置校验、脱敏及原子保存
- requestwatch/tcp_streams.py：持久化TCP双向序列重组及全文搜索
- requestwatch/dockerinfo.py：Docker 容器归属
- requestwatch/proxy.py / proxy_addon.py：mitmproxy 进程及 HTTP/HTTPS 捕获
- requestwatch/replay.py：HTTP/TCP/UDP 新连接重发
- requestwatch/static/：中文 Web 操作台
- deploy/、scripts/：Ubuntu/systemd 安装与恢复
- tests/：逻辑及本地集成验证

实现参考：[mitmproxy 证书](https://docs.mitmproxy.org/stable/concepts/certificates/)、[NetfilterQueue API 与限制](https://github.com/oremanj/python-netfilterqueue)、[Scapy 抓包](https://scapy.readthedocs.io/en/stable/usage.html)。

## 开源许可证

RequestWatch 以 **GNU Affero General Public License v3.0 only（AGPL-3.0-only）** 发布，完整条款见 [LICENSE](LICENSE)。项目版权声明见 [NOTICE](NOTICE)。

源码仓库：https://github.com/10dian-ai/RequestWatch 。第三方依赖保留各自许可证。修改版本对外提供网络服务时，应按 AGPL 要求向用户提供对应源码，并把界面的源码链接指向该版本的源码。
