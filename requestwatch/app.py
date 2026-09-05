from __future__ import annotations

import asyncio
import base64
import hmac
import json
import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .config import Config
from .replay import replay_http, replay_packet, validate_http_edits
from .rules import RuleInput
from .runtime import Runtime
from .store import Store

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
    store = Store(config.data_dir / ("demo.sqlite3" if config.demo else "requestwatch.sqlite3"), config.max_records)
    from .dockerinfo import DockerInventory
    from .network import NetworkEngine
    from .proxy import ProxyProcess

    inventory = DockerInventory()
    runtime = Runtime(store, config, inventory if not config.demo else None)
    network, proxy = NetworkEngine(runtime, config), ProxyProcess(config)
    stop = threading.Event()
    maintenance_thread = None

    def maintenance():
        while not stop.wait(1):
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
        store.close()

    app = FastAPI(title="RequestWatch", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.runtime, app.state.config, app.state.store = runtime, config, store

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
        return {"status": "ok"}

    @api.get("/status")
    def status():
        demo_status = {"running": False, "state": "demo", "detail": "演示模式，不操作真实网络"}
        return {"mode": "demo" if config.demo else "live", "port": config.port, "proxy_port": config.proxy_port,
                "proxy_host": config.proxy_host, "capture": demo_status if config.demo else network.status(),
                "proxy": demo_status if config.demo else proxy.status(), "docker": demo_status if config.demo else inventory.status(),
                "stats": store.stats(), "protected_ports": config.protected_ports, "max_records": config.max_records}

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
                duplicate = apply_demo_edits(record, body.edits)
            except (ValueError, TypeError) as exc:
                raise HTTPException(400, str(exc)) from exc
            for key in ("id", "created_at", "deadline", "rule_id", "rule_name"):
                duplicate.pop(key, None)
            duplicate.update(state="replayed", replay_of=record_id, detail="演示重发：未发送真实网络流量")
            return runtime.ingest(duplicate)
        try:
            result = replay_http(record, body.edits) if record["source"] == "http" else replay_packet(record, body.edits)
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
