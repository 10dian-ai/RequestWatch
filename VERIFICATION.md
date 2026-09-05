# 验证记录

日期：2026-09-05。开发机：Windows，Python 3.14.7；目标部署：Ubuntu，Python 3.12+。

## 已执行

- 完整 Python 回归（开启真实 app 集成）：104 passed，4 skipped，4 subtests passed。
- 独立 mitmproxy 环境的真实代理验证：27 passed，包含 HTTP / HTTPS、代理鉴权、测试 CA 信任、编辑后放行、丢弃不会到达上游。
- 主程序全链路：真实 FastAPI + mitmdump + 本地 origin，规则暂停、正文/URL/方法/重复头编辑、响应内容搜索与重发通过。
- HTTP、TCP、UDP 真实本地回显重发通过；不依赖外部网站。
- Chromium 浏览器：登录/错误令牌、正文搜索、跨刷新保留草稿、重发、规则创建、模拟暂停/编辑/放行/丢弃、容器展示均通过；1440px 桌面与390px手机布局无页面横向溢出，未出现JavaScript异常。
- Python compileall、JavaScript node --check、Ubuntu安装脚本 bash -n 通过。

完整回归中的3项代理测试因主环境没有直接安装mitmproxy而跳过，已在独立代理环境执行通过。剩余1项跳过的是Linux真实内核集成。

## 未在当前机器执行

- Ubuntu 内核 NFQUEUE 实际拦截、systemd 运行。
- Docker bridge、rootless、host 网络及目标容器真实流量归属。
- 实际Ubuntu服务器部署和目标应用CA安装。

项目提供 tests/test_linux_integration.py，需在Ubuntu以root显式设置 RW_RUN_LINUX_INTEGRATION=1 运行。该测试在全新的 unshare 网络命名空间内操作，先校验隔离状态，仅使用lo，不修改宿主机防火墙。验证 UDP 暂停、修改、丢弃、超时，TCP等长修改及规则清理。

## 复验

```bash
.venv/bin/python -m pip install '.[test,linux,proxy]'
RW_RUN_APP_INTEGRATION=1 RW_RUN_PROXY_INTEGRATION=1 .venv/bin/python -m pytest -q
sudo env RW_RUN_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_linux_integration.py -q
```

浏览器冒烟脚本：tests/ui-smoke.cjs。需要 playwright-core 和 Chromium；可用 RW_BROWSER_PATH 指定浏览器，RW_UI_URL / RW_UI_TOKEN 指定**演示模式**控制台。它会在演示数据库创建测试规则和记录，不应用于真实服务器。

## GitHub 开源发布与一键部署验证

- 发布许可证为 AGPL-3.0-only；Python wheel 构建成功，METADATA 的 License-Expression 与内置 LICENSE 文件已检查。
- 11 项核心回归通过；Web UI 的许可证/源码入口及390px布局检查通过。
- 一键引导与安装器命令桩测试：26 passed，1 skipped。覆盖环境检查、ref选择、下载失败、危险归档、清理、首次安装、重复升级数据保留、实际访问地址输出和服务启动失败。
- 跳过项为Linux符号链接目标测试，当前Windows不具备对应测试条件。未执行真实Ubuntu apt/systemd安装。
- bootstrap.sh 与 install-ubuntu.sh 均通过 bash -n。
