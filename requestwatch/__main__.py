import argparse
import logging

import uvicorn

from .app import create_app
from .config import Config


def main():
    parser = argparse.ArgumentParser(description="RequestWatch · Ubuntu / Docker 网络操作台")
    parser.add_argument("--host", help="Web UI 监听地址；远程访问使用 0.0.0.0")
    parser.add_argument("--port", type=int, help="Web UI 端口，默认 7030")
    parser.add_argument("--data-dir", help="数据库、令牌和 CA 保存目录")
    parser.add_argument("--demo", action="store_true", help="演示界面，不捕获、拦截或发送真实流量")
    parser.add_argument("--no-capture", action="store_true", help="关闭 Linux 原始抓包，仅使用代理")
    parser.add_argument("--no-proxy", action="store_true", help="关闭 HTTP/HTTPS 代理")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    rollback_settings = None
    rollback_directory = None
    rollback_notice = False
    while True:
        config = Config()
        for name in ("host", "port", "data_dir"):
            value = getattr(args, name)
            if value is not None:
                setattr(config, name, value)
        config.demo = args.demo
        config.capture_enabled &= not args.no_capture
        config.proxy_enabled &= not args.no_proxy
        server = None
        restart_requested = False
        try:
            app = create_app(config)
            server = uvicorn.Server(uvicorn.Config(app, host=config.host, port=config.port, workers=1, access_log=False))
            def request_restart():
                nonlocal restart_requested
                restart_requested = True
                server.should_exit = True
            def listener_addresses():
                return [(sock.family, sock.getsockname()[0], sock.getsockname()[1])
                        for listener in getattr(server, "servers", []) for sock in (listener.sockets or [])]
            app.state.request_restart = request_restart
            app.state.listener_addresses = listener_addresses
            app.state.restart_rollback = rollback_notice
            print(f"Web UI: http://{config.host}:{config.port}")
            token_dir = config.data_dir / "demo" if config.demo else config.data_dir
            print(f"访问令牌文件: {token_dir / 'admin-token'}")
            print("演示模式：不操作真实网络" if config.demo else "真实流量模式；HTTPS 需要配置代理及信任 CA")
            server.run()
            if not server.started and rollback_settings is not None:
                raise RuntimeError("New settings did not start successfully")
        except (Exception, SystemExit):
            if rollback_settings is None or (server is not None and server.started):
                raise
            from .settings import SettingsStore
            SettingsStore(rollback_directory).save(rollback_settings, base=rollback_settings)
            rollback_settings = None
            rollback_notice = True
            logging.getLogger(__name__).error("新设置启动失败，已恢复上次可用设置并重新启动；请在原地址使用原令牌登录")
            continue
        if not restart_requested:
            break
        rollback_settings = config.settings_values()
        rollback_directory = config.data_dir
        rollback_notice = False
        logging.getLogger(__name__).info("Applying settings and restarting RequestWatch")


if __name__ == "__main__":
    main()
