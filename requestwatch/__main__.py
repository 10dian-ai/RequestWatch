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
    config = Config()
    for name in ("host", "port", "data_dir"):
        value = getattr(args, name)
        if value is not None:
            setattr(config, name, value)
    config.demo = args.demo
    config.capture_enabled &= not args.no_capture
    config.proxy_enabled &= not args.no_proxy
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = create_app(config)
    print(f"Web UI: http://{config.host}:{config.port}")
    print(f"访问令牌文件: {config.data_dir / 'admin-token'}（配置了 RW_TOKEN 时使用环境中的令牌）")
    print("演示模式：不操作真实网络" if config.demo else "真实流量模式；HTTPS 需要配置代理及信任 CA")
    uvicorn.run(app, host=config.host, port=config.port, workers=1, access_log=False)


if __name__ == "__main__":
    main()
