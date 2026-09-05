from __future__ import annotations

import asyncio
import base64
import hmac
from contextlib import ExitStack
import json
import logging
import os
import socket
import tempfile
import time
import uuid
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import BackgroundTasks, APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .config import Config
from .replay import replay_http, replay_packet, validate_http_edits
from .rules import RuleInput
from .runtime import Runtime
from .store import Store
from .settings import SettingsError, public_settings

logger = logging.getLogger(__name__)


class DecisionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["accept", "drop"]
    edits: dict = Field(default_factory=dict)


class ReplayInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    edits: dict = Field(default_factory=dict)


def create_app(config: Config | None = None) -> FastAPI:
    config = config or Config()
    config.prepare()
    store = Store(config.data_dir / ("demo.sqlite3" if config.demo else "requestwatch.sqlite3"), config.max_records,
                  body_dir=config.data_dir / "demo" if config.demo else config.data_dir)
    from .dockerinfo import DockerInventory
    from .network import NetworkEngine
    from .proxy import ProxyProcess

    from .tcp_streams import TCPStreamStore
    streams = TCPStreamStore(config.data_dir / ("demo-streams" if config.demo else "streams"), max_sessions=config.max_records, idle_timeout=config.tcp_idle_timeout)
    inventory = DockerInventory()
    runtime = Runtime(store, config, inventory if not config.demo else None, streams)
    network, proxy = NetworkEngine(runtime, config), ProxyProcess(config)
    stop = threading.Event()
    maintenance_thread = None

    def maintenance():
        ticks = 0
        while not stop.wait(1):
            ticks += 1
            if ticks % 60 == 0:
                try:
                    store.gc_bodies()
                except Exception:
                    logger.exception("Body retention cleanup failed")
            if config.demo:
                runtime.demo_tick()
            elif int(__import__("time").monotonic()) % 5 == 0:
                try:
                    inventory.refresh()
                except Exception:
                    logger.exception("Docker inventory refresh failed")

    @asynccontextmanager
    async def lifespan(app):
        nonlocal maintenance_thread
        if config.demo:
            from .demo import seed
            seed(runtime)
        else:
            fd, marker = tempfile.mkstemp(prefix=".runtime-", dir=config.data_dir)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump({"active_queue_num": config.queue_num}, stream)
                os.replace(marker, config.data_dir / "runtime.json")
            finally:
                if os.path.exists(marker):
                    os.unlink(marker)
            await asyncio.to_thread(inventory.refresh)
            for engine in (network, proxy):
                try:
                    await asyncio.to_thread(engine.start)
                except Exception:
                    logger.exception("Engine start failed")
        maintenance_thread = threading.Thread(target=maintenance, name="requestwatch-maintenance", daemon=True)
        maintenance_thread.start()
        yield
        stop.set()
        if maintenance_thread:
            maintenance_thread.join(timeout=2)
        if not config.demo:
            for engine in (network, proxy):
                try:
                    await asyncio.to_thread(engine.stop)
                except Exception:
                    logger.exception("Engine stop failed")
        streams.close()
        store.close()

    app = FastAPI(title="RequestWatch", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.runtime, app.state.config, app.state.store = runtime, config, store
    app.state.streams = streams
    app.state.request_restart = None
    app.state.listener_addresses = None
    app.state.restart_rollback = False
    instance_id = uuid.uuid4().hex
    settings_store = config._settings_store
    current_settings = config.settings_values()
    restart_scheduled = False
    settings_lock = threading.RLock()

    async def authenticated(authorization: str = Header(default="")):
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(value.encode(), config.token.encode()):
            raise HTTPException(401, "访问令牌无效", headers={"WWW-Authenticate": "Bearer"})

    api = APIRouter(prefix="/api", dependencies=[Depends(authenticated)])

    @app.middleware("http")
    async def response_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    def health():
        return {"status": "ok", "instance_id": instance_id, "restart_rollback": app.state.restart_rollback}

    @api.get("/status")
    def status():
        demo_status = {"running": False, "state": "demo", "detail": "演示模式，不操作真实网络"}
        return {"mode": "demo" if config.demo else "live", "port": config.port, "proxy_port": config.proxy_port,
                "proxy_host": config.proxy_host, "capture": demo_status if config.demo else network.status(),
                "proxy": demo_status if config.demo else proxy.status(), "docker": demo_status if config.demo else inventory.status(),
                "stats": store.stats(), "protected_ports": config.protected_ports, "max_records": config.max_records,
                "default_timeout_seconds": config.default_timeout_seconds, "instance_id": instance_id}

    def settings_response():
        saved = {**current_settings, **settings_store.load()}
        return {"current": public_settings(current_settings), "saved": public_settings(saved),
                "pending": sorted(key for key in saved if saved[key] != current_settings.get(key)),
                "restart_supported": config.demo or callable(app.state.request_restart),
                "instance_id": instance_id, "demo": config.demo,
                "settings_path": str(settings_store.path), "data_dir": str(config.data_dir),
                "interfaces": [name for _, name in socket.if_nameindex()],
                "restart_rollback": app.state.restart_rollback,
                "source": "Web 设置覆盖环境和命令行初始值"}

    @api.get("/settings")
    def read_settings():
        with settings_lock:
            try:
                return settings_response()
            except SettingsError as exc:
                raise HTTPException(500, str(exc)) from exc

    @api.put("/settings")
    def write_settings(values: dict):
        with settings_lock:
            if restart_scheduled:
                raise HTTPException(409, "正在重启，请在服务恢复后修改设置")
            try:
                settings_store.save(values, base=current_settings)
                return settings_response()
            except SettingsError as exc:
                raise HTTPException(400, str(exc)) from exc

    def preflight_settings(values):
        if values["capture_enabled"] and values["interfaces"] != "any":
            available = {name for _, name in socket.if_nameindex()}
            missing = set(values["interfaces"].split(",")) - available
            if missing:
                raise ValueError("网卡不存在：" + ", ".join(sorted(missing)))
        callback = app.state.listener_addresses
        if callable(callback):
            owned = callback()
        else:
            owned = [(entry[0], entry[4][0], config.port) for entry in socket.getaddrinfo(config.host, config.port, type=socket.SOCK_STREAM)]
        if proxy.status().get("running"):
            owned += [(entry[0], entry[4][0], config.proxy_port) for entry in socket.getaddrinfo(config.proxy_host, config.proxy_port, type=socket.SOCK_STREAM)]
        listeners = [(values["host"], values["port"])]
        if values["proxy_enabled"]:
            listeners.append((values["proxy_host"], values["proxy_port"]))
        tested = set()
        # Uvicorn binds every resolved address, including localhost's IPv4 and IPv6.
        with ExitStack() as probes:
            for host, port in listeners:
                try:
                    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                    for family, socktype, proto, _, address in addresses:
                        key = (family, address)
                        if key in tested:
                            continue
                        tested.add(key)
                        ip = address[0]
                        overlaps_own = any(family == f and port == p and (ip == addr or ip in {"0.0.0.0", "::"} or addr in {"0.0.0.0", "::"}) for f, addr, p in owned)
                        probe_address = (ip, 0, *address[2:]) if overlaps_own else address
                        listener = probes.enter_context(socket.socket(family, socktype, proto))
                        if family == socket.AF_INET6:
                            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        listener.bind(probe_address)
                except OSError as exc:
                    raise ValueError(f"监听地址 {host}:{port} 不可用（地址不属于本机或端口已占用）") from exc
        if values["proxy_enabled"]:
            import shutil
            custom = values.get("mitmdump", "")
            if custom and not (shutil.which(custom) or Path(custom).is_file()):
                raise ValueError("指定的 mitmdump 程序不存在")

    @api.post("/settings/apply")
    def apply_settings(background_tasks: BackgroundTasks):
        nonlocal restart_scheduled, current_settings
        with settings_lock:
            if restart_scheduled:
                raise HTTPException(409, "服务已经准备重启，请稍候")
            try:
                values = {**current_settings, **settings_store.load()}
                if not config.demo:
                    if not callable(app.state.request_restart):
                        raise HTTPException(409, "当前启动方式不支持面板重启，请使用 requestwatch 命令或一键安装服务启动")
                    preflight_settings(values)
            except (SettingsError, ValueError) as exc:
                raise HTTPException(400, str(exc)) from exc
            response = {"ok": True, "restarting": not config.demo, "demo": config.demo,
                        "instance_id": instance_id, "next": {"host": values["host"], "port": values["port"],
                        "token_changed": values["token"] != current_settings["token"]}}
            if config.demo:
                current_settings = values
                return response
            restart_scheduled = True
            def trigger_restart():
                time.sleep(0.5)
                app.state.request_restart()
            background_tasks.add_task(trigger_restart)
            return response

    @api.get("/records")
    def records(q: str = Query(default="", max_length=512), protocol: str = "", container_id: str = "", state: str = "", source: str = "",
                limit: int = Query(default=100, ge=1, le=200), offset: int = Query(default=0, ge=0)):
        return store.query(q=q, protocol=protocol, container_id=container_id, state=state, source=source, limit=limit, offset=offset)

    def get_record(record_id: str):
        record = store.get(record_id)
        if not record:
            raise HTTPException(404, "记录不存在或已超过保留数量")
        return record

    @api.get("/records/{record_id}")
    def record_detail(record_id: str):
        return get_record(record_id)

    @api.get("/records/{record_id}/export")
    def export_record(record_id: str):
        record = get_record(record_id)
        # Never embed an untrusted captured field in Content-Disposition.
        return JSONResponse(record, headers={"Content-Disposition": 'attachment; filename="requestwatch-record.json"'})

    def body_available(record, side):
        if record.get("source") != "http":
            raise HTTPException(400, "此记录是原始网络包，请查看 TCP 会话或包内容")
        if side == "response" and not any("response" + suffix in record for suffix in ("_body_ref", "_body_text", "_body_b64")):
            raise HTTPException(404, "尚未捕获响应正文")

    @api.get("/records/{record_id}/body/{side}")
    def record_body(record_id: str, side: Literal["request", "response"], view: Literal["text", "raw"] = "text", download: bool = False):
        record = get_record(record_id)
        body_available(record, side)
        ref = record.get(side + ("_text_ref" if view == "text" else "_body_ref"))
        media = "text/plain; charset=utf-8" if view == "text" else "application/octet-stream"
        filename = "requestwatch-" + side + (".txt" if view == "text" else ".bin")
        headers = {"X-Body-Complete": str(not record.get(side + "_truncated", False) and record.get(side + "_body_complete", True)).lower()}
        try:
            if ref:
                path = store.bodies.path(ref)
                if not path.is_file():
                    raise FileNotFoundError()
                return FileResponse(path, media_type=media, filename=filename if download else None, headers=headers)
            value = store.bodies.read_text(record, side).encode("utf-8") if view == "text" else store.bodies.read_body(record, side)
        except (OSError, ValueError) as exc:
            raise HTTPException(410, "正文文件不可用，无法恢复完整内容，请重新抓取") from exc
        if download:
            headers["Content-Disposition"] = 'attachment; filename="' + filename + '"'
        return Response(value, media_type=media, headers=headers)

    @api.get("/records/{record_id}/message/{side}")
    def full_http_message(record_id: str, side: Literal["request", "response"]):
        record = get_record(record_id)
        body_available(record, side)
        if record.get(side + "_truncated") or record.get(side + "_body_complete") is False:
            raise HTTPException(409, "这条历史记录的正文不完整，请下载已有正文或重新抓取")
        # Reconstruct an application-level HTTP message, not HTTP/2 frames/chunk boundaries.
        headers = record.get(side + "_headers", [])
        ref = record.get(side + "_body_ref")
        try:
            path = store.bodies.path(ref) if ref else None
            size = path.stat().st_size if path else len(store.bodies.read_body(record, side))
        except (OSError, ValueError) as exc:
            raise HTTPException(410, "完整正文文件不可用") from exc
        if side == "request":
            target = urlsplit(record.get("url", ""))
            line = str(record.get("method", "GET")) + " " + (target.path or "/") + (("?" + target.query) if target.query else "") + " HTTP/1.1"
        else:
            line = "HTTP/1.1 " + str(record.get("status_code", 200)) + " " + str(record.get("reason", ""))
        exported = [(str(k), str(v)) for k, v in headers if str(k).lower() not in {"content-length", "transfer-encoding", "trailer"} and not str(k).startswith(":")]
        # Preserve trailer values as headers when removing HTTP/1 chunk framing.
        exported.extend((str(k), str(v)) for k, v in record.get(side + "_trailers", []))
        exported.append(("Content-Length", str(size)))
        if side == "request" and not any(k.lower() == "host" for k, _ in exported):
            exported.append(("Host", urlsplit(record.get("url", "")).netloc))
        head = (line + "\r\n" + "\r\n".join(k + ": " + v for k, v in exported) + "\r\n\r\n").encode("utf-8", errors="replace")
        def chunks():
            yield head
            if path:
                with path.open("rb") as stream:
                    while chunk := stream.read(256 * 1024):
                        yield chunk
            else:
                yield store.bodies.read_body(record, side)
        return StreamingResponse(chunks(), media_type="application/octet-stream", headers={
            "Content-Disposition": 'attachment; filename="requestwatch-' + side + '.http"',
            "X-RequestWatch-Export": "reconstructed-http-1.1", "Content-Length": str(len(head) + size)})

    @api.get("/sessions")
    def tcp_sessions(q: str = Query(default="", max_length=512), container_id: str = "",
                     limit: int = Query(default=100, ge=1, le=200), offset: int = Query(default=0, ge=0)):
        return streams.list_sessions(q=q, container_id=container_id, limit=limit, offset=offset)

    def get_session(session_id):
        session = streams.get(session_id)
        if not session:
            raise HTTPException(404, "TCP 会话不存在或已超过保留数量")
        return session

    @api.get("/sessions/{session_id}")
    def tcp_session(session_id: str):
        return get_session(session_id)

    @api.get("/sessions/{session_id}/body/{direction}")
    def tcp_session_body(session_id: str, direction: Literal["client", "server"], view: Literal["raw", "text", "latin1"] = "text", download: bool = False):
        session = get_session(session_id)
        try:
            path = streams.body_path(session_id, direction, view)
        except (OSError, ValueError, KeyError) as exc:
            raise HTTPException(410, "TCP 会话文件不可用") from exc
        return FileResponse(path, media_type="application/octet-stream" if view == "raw" else "text/plain; charset=utf-8",
                            filename=("requestwatch-tcp-" + direction + (".bin" if view == "raw" else ".txt")) if download else None,
                            headers={"X-Body-Complete": str(bool(session.get("complete"))).lower()})

    @api.get("/containers")
    def containers():
        if config.demo:
            from .demo import CONTAINERS
            return {"items": CONTAINERS, "status": {"state": "demo"}}
        return {"items": inventory.list(), "status": inventory.status()}

    @api.get("/rules")
    def rules():
        return {"items": runtime.rules()}

    def save_rule(body: RuleInput, rule_id: str | None = None):
        rules = runtime.rules()
        if rule_id and not any(r["id"] == rule_id for r in rules):
            raise HTTPException(404, "规则不存在")
        if not rule_id and len(rules) >= 100:
            raise HTTPException(400, "最多支持 100 条拦截规则")
        rule = body.model_dump()
        if "timeout_seconds" not in body.model_fields_set:
            rule["timeout_seconds"] = config.default_timeout_seconds
        if rule_id:
            rule["id"] = rule_id
        result = store.save_rule(rule)
        runtime.refresh_rules()
        return result

    @api.post("/rules")
    def create_rule(body: RuleInput):
        return save_rule(body)

    @api.put("/rules/{rule_id}")
    def update_rule(rule_id: str, body: RuleInput):
        return save_rule(body, rule_id)

    @api.delete("/rules/{rule_id}")
    def delete_rule(rule_id: str):
        if not store.delete_rule(rule_id):
            raise HTTPException(404, "规则不存在")
        runtime.refresh_rules()
        return {"ok": True}

    @api.post("/records/{record_id}/decision")
    def decision(record_id: str, body: DecisionInput):
        record = get_record(record_id)
        edits = body.edits if body.action == "accept" else {}
        try:
            if record["source"] == "http":
                validate_http_edits(edits)
            elif edits:
                if config.demo:
                    payload = bytes.fromhex(edits.get("payload_hex", ""))
                    if record["protocol"] == "TCP" and len(payload) != record["payload_size"]:
                        raise ValueError("TCP 原始包修改必须保持字节长度一致")
                else:
                    from .network import validate_packet_edit
                    validate_packet_edit(record, edits)
            runtime.resolve(record_id, body.action, edits)
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"ok": True, "state": "resolving"}

    @api.post("/records/{record_id}/replay")
    def replay(record_id: str, body: ReplayInput):
        record = get_record(record_id)
        if record["state"] in {"pending", "resolving"}:
            raise HTTPException(409, "请先处理原请求的拦截，再进行重发")
        if config.demo:
            from .demo import apply_demo_edits
            try:
                duplicate = apply_demo_edits(record, body.edits, store.bodies)
            except (ValueError, TypeError) as exc:
                raise HTTPException(400, str(exc)) from exc
            for key in ("id", "created_at", "deadline", "rule_id", "rule_name"):
                duplicate.pop(key, None)
            duplicate.update(state="replayed", replay_of=record_id, detail="演示重发：未发送真实网络流量")
            return runtime.ingest(duplicate)
        try:
            result = replay_http(record, body.edits, store.bodies) if record["source"] == "http" else replay_packet(record, body.edits)
            return runtime.ingest(result)
        except (ValueError, TypeError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @api.get("/ca")
    def certificate():
        cert = config.data_dir / "mitmproxy" / "mitmproxy-ca-cert.pem"
        if not cert.is_file():
            raise HTTPException(404, "CA 尚未生成，请先启动 HTTPS 代理")
        return FileResponse(cert, media_type="application/x-pem-file", filename="requestwatch-ca-cert.pem")

    @api.post("/internal/ingest")
    def internal_ingest(record: dict):
        if record.get("source") != "http" or record.get("protocol") not in {"HTTP", "HTTPS"}:
            raise HTTPException(400, "内部接口只接收 HTTP 代理流")
        if len(json.dumps(record)) > 8 * 1024 * 1024:
            raise HTTPException(413, "流记录超过存储上限")
        record["state"] = "captured"
        captured = runtime.ingest(record, can_intercept=True)
        return {key: captured[key] for key in ("id", "state", "timeout_seconds", "deadline") if key in captured}

    @api.get("/internal/decision/{record_id}")
    def internal_decision(record_id: str):
        return {"decision": runtime.take_decision(record_id)}

    @api.put("/internal/records/{record_id}")
    def internal_update(record_id: str, changes: dict):
        record = get_record(record_id)
        if record["source"] != "http":
            raise HTTPException(400, "内部接口只更新 HTTP 代理流")
        if len(json.dumps(changes)) > 8 * 1024 * 1024:
            raise HTTPException(413, "流记录超过存储上限")
        changes.pop("source", None)
        runtime.update(record_id, changes)
        return {"ok": True}

    @api.post("/demo/intercept")
    def demo_intercept():
        if not config.demo:
            raise HTTPException(404, "仅演示模式可用")
        from .demo import intercept_example
        result = intercept_example(runtime)
        if not result:
            raise HTTPException(400, "请先创建并启用至少一条规则")
        return result

    app.include_router(api)
    static_dir = Path(__file__).parent / "static"
    static_dir.mkdir(exist_ok=True)
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="web")
    return app
