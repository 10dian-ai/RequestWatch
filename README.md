# RequestWatch

[源码仓库](https://github.com/10dian-ai/RequestWatch) · [AGPL-3.0-only](LICENSE) · [验证记录](VERIFICATION.md)

部署在 Ubuntu 的本机与 Docker 网络调试工具。**Web UI 默认端口 7030**，HTTP/HTTPS 代理默认端口 8080。

通过中文操作台搜索请求与网络包、按容器筛选、设置暂停规则、编辑后放行、丢弃和重发。项目包含真实抓包/代理引擎；演示模式单独运行，不操作真实网络。

## 一键部署（Ubuntu 24.04+）

在 Ubuntu 服务器执行：

```bash
curl -fsSL https://raw.githubusercontent.com/10dian-ai/RequestWatch/main/scripts/bootstrap.sh | sudo bash
```

安装完成后访问 **http://服务器IP:7030**，使用以下命令查看登录令牌：

```bash
sudo cat /var/lib/requestwatch/admin-token
```

脚本下载本仓库源码，安装运行依赖，配置 systemd 并启动服务；重复执行可更新程序，保留已有配置、数据库和 CA。默认代理只监听本机8080，Docker容器接入方法见后文。需要服务器能访问 GitHub 和 Ubuntu/PyPI 软件源。

如需固定版本，可把安装命令末尾改为 `sudo env RW_REF=<分支名或版本标签或commit> bash`。这固定下载的项目源码版本；引导脚本本身仍来自命令中指定的 main。

## 第一版能力

| 能力 | TCP / UDP 原始包 | HTTP / HTTPS 代理 |
| --- | --- | --- |
| 捕获与查看 | IPv4 / IPv6 TCP、UDP，载荷文本和 HEX | 方法、URL、请求头、正文、响应、状态码 |
| 内容搜索 | 当前捕获包内可解码的文本 | URL、头、解码后的请求与响应正文 |
| 容器筛选 | 按源/目标容器 IP 归属 | 按连接到代理的客户端 IP 归属 |
| 规则暂停 | 容器、目标 IP/CIDR、端口、包内关键词 | 容器、目标主机、端口、请求关键词 |
| 编辑后放行 | TCP 等长载荷修改；UDP 更新长度/校验和 | 支持修改方法、URL、重复请求头和正文 |
| 丢弃 | 丢弃当前包；发送方可能重传 | 返回本地 499，不向上游发送该请求 |
| 重发 | 使用宿主机新 TCP 连接或新 UDP 数据报 | 使用宿主机新 HTTP 请求，保留原始二进制正文 |

规则内条件全部满足才暂停，多条规则按创建顺序命中第一条。默认等待 30 秒，可设为 5–120 秒，超时放行原始内容。原始包暂停与代理暂停是两个独立接入路径。

## Ubuntu 安装

建议 Ubuntu 24.04 LTS 或更新版本，Python 3.12+，root 权限；支持 Docker Engine。将整个项目上传到服务器，然后在项目根目录执行：

```bash
sudo bash scripts/install-ubuntu.sh
sudo systemctl status requestwatch
sudo cat /var/lib/requestwatch/admin-token
```

访问 **http://服务器IP:7030**，输入上面的令牌。安装脚本默认 Web UI 监听 0.0.0.0:7030，防火墙应允许你的管理设备访问。原始抓包引擎和 HTTP 代理的实际状态会显示在页面中。

脚本安装到 /opt/requestwatch，创建 Python 虚拟环境和 systemd 服务。数据、CA 私钥及令牌存放于 /var/lib/requestwatch。现有配置和数据在重新安装时保留。

```bash
sudoedit /etc/requestwatch/requestwatch.env
sudo systemctl restart requestwatch
sudo journalctl -u requestwatch -f
```

默认排除 22、7030、8080 的双向网络流量，防止 SSH 和管理/代理流量进入原始抓包反馈循环。**SSH 使用其他端口时，请先在 RW_PROTECTED_PORTS 中追加该端口。** 保护范围不阻止你在 HTTP 代理内调试其他应用的 HTTPS 请求。

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

演示令牌位于 data/admin-token。页面明确显示演示标识。创建一条规则后，使用「生成匹配演示请求」体验暂停、编辑、放行、丢弃；演示重发只创建模拟记录。演示数据库与真实数据库分开。

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

1. 将 /etc/requestwatch/requestwatch.env 中的 RW_PROXY_HOST 改为可达的宿主机 bridge 地址，或 0.0.0.0。
2. 重启 requestwatch。
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

代理可被其他设备访问时，设置 RW_PROXY_AUTH=user:password 并限制防火墙来源。目标客户端代理 URL 需包含对应用户名/密码，特殊字符需 URL 编码。7030 的管理令牌与代理认证是两套独立凭据。

## 操作流程

1. 打开 7030 页面登录，确认抓包/代理引擎状态。
2. 在「网络流量」叠加关键词、协议、容器和状态筛选；点击记录查看请求、响应、概要或 HEX。
3. 在「拦截规则」创建窄范围规则。原始包目标地址支持 IP/CIDR；HTTP 支持目标主机文字匹配。
4. 命中规则后打开「拦截队列」，选择记录。直接放行或编辑后放行；丢弃则终止对应包/HTTP 请求。
5. 已处理记录可以「重发请求」。HTTP 重发支持编辑完整请求；TCP/UDP 重发只发送所选应用载荷。
6. 页面每 2 秒刷新，可暂停刷新；刷新不会覆盖尚未提交的编辑草稿。记录可以导出 JSON。

响应正文支持搜索，但**请求发送前的暂停规则不能匹配未来尚未收到的响应**。原始包关键词不会跨 TCP 分段重组；需要完整 HTTP 请求/响应时使用代理路径。

## 范围和实际限制

- HTTPS 解密需要目标客户端经过代理且信任 CA。证书固定、独立信任库、忽略代理的程序需要另行适配。非 HTTP 的 TLS/QUIC 数据仍是密文。
- 这是单机调试工具，没有集群、用户角色、流量审计服务或线速采集承诺。原始包使用有界用户态缓冲，页面会报告被动采集丢包计数。
- 启用原始包规则时，符合协议且不在保护端口中的包先进入 NFQUEUE，再由用户态精确匹配。高负载会增加延迟；内核队列满可能丢包。--queue-bypass 只解决没有监听进程的情况，不保证内核队列满时放行。
- 系统规则只新增本项目命名的 mangle 链及带注释的跳转，不清空 Docker、防火墙规则或修改默认策略。关闭原始包规则/正常停止服务会移除跳转并处理等待包；systemd 退出后还执行定向清理。
- Python NetfilterQueue 绑定对较大的包可能截断。截断包、IP 分片和不适合修改的特殊 IPv6 头禁止编辑。TCP 只能等长修改，并用有界 5 分钟缓存处理重传；超长连接不保证无限期重传一致性。
- TCP 原始包丢弃不是取消应用请求；发送方可能再次重传。TCP 载荷重发不是原连接恢复，不复用原序列号、TLS 握手或容器身份。新连接的结果取决于应用协议；UDP 也可能因认证或状态要求不能独立重发。
- 抓取宿主机可见的网络接口并动态识别新增接口。容器内部 loopback 不经过宿主机网络；某些 bridge 路径是否经过 Netfilter 依赖 br_netfilter 配置。此类路径不承诺全部可见。
- 容器归属基于 Docker 公共网络 IP。host 网络、共享 IP、rootless Docker、NAT 后地址及跨命名空间路径可能显示「未知来源」；不会伪造精确归属。Docker socket 查询只读，但进程按用户选择以 root 运行。
- HTTP 正文保存原始字节和解码文本，各自最多 1 MiB，并显示截断标识；完整代理流仍由 mitmproxy 转发。截断正文重发需提供完整替换内容。长连接/WebSocket消息并未单独解析。
- 默认保留最近 10000 条记录，SQLite 复用已分配空间。数据库包含捕获到的正文和请求头，应按你的数据需求管理 /var/lib/requestwatch。

## 配置项

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| RW_HOST | 127.0.0.1（安装服务为0.0.0.0） | Web监听地址 |
| RW_PORT | 7030 | Web端口 |
| RW_DATA_DIR | data（安装服务为/var/lib/requestwatch） | 持久数据 |
| RW_TOKEN | 自动生成并保存 | Web/API令牌，至少16字符 |
| RW_CAPTURE | true | 启用Linux抓包 |
| RW_INTERFACES | any | 全部接口，或逗号分隔的接口名 |
| RW_QUEUE_NUM | 7030 | 独占NFQUEUE编号 |
| RW_PROTECTED_PORTS | 22 | 排除端口，自动追加Web/代理端口 |
| RW_MAX_RECORDS | 10000 | 记录保留上限，至少100 |
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
