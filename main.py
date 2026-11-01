"""Small Elasticsearch cluster dashboard and query proxy."""

from __future__ import annotations

import base64
import asyncio
import json
import os
import re
import secrets
import ssl
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

import httpx
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


ROOT = Path(__file__).parent
ES_TIMEOUT = float(os.getenv("ES_TIMEOUT", "8"))
FLEET_AGENTS_LIMIT = max(1, int(os.getenv("FLEET_AGENTS_LIMIT", "10000")))
CONFIG_FILE = ROOT / "config.json"
CA_CERT_FILE = ROOT / "ca.pem"
AUTH_COOKIE = "elastic_desk_session"
AUTH_SESSION_TTL = 12 * 60 * 60
AUTH_PASSWORD_HASH: str | None = None
AUTH_HASH_FROM_ENV = False
AUTH_ENABLED = False
AUTH_SESSIONS: dict[str, float] = {}
AUTH_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
PASSWORD_HASHER = PasswordHasher()


def load_config() -> dict:
    try:
        saved = json.loads(CONFIG_FILE.read_text())
        if isinstance(saved, dict):
            return saved
    except (OSError, ValueError):
        pass
    return {}


_saved_config = load_config()
_ui_auth_config = _saved_config.get("ui_auth")
_configured_auth_hash = _ui_auth_config.get("password_hash") if isinstance(_ui_auth_config, dict) else None
_environment_auth_hash = os.getenv("UI_AUTH_PASSWORD_HASH", "").strip()
AUTH_HASH_FROM_ENV = bool(_environment_auth_hash)
_active_auth_hash = _environment_auth_hash or _configured_auth_hash
if isinstance(_active_auth_hash, str) and _active_auth_hash:
    AUTH_PASSWORD_HASH = _active_auth_hash
elif _ui_auth_config is not None:
    AUTH_PASSWORD_HASH = "$invalid-ui-auth-config$"

_auth_enabled_env = os.getenv("UI_AUTH_ENABLED")
if _auth_enabled_env is not None:
    _normalized_auth_enabled = _auth_enabled_env.strip().lower()
    if _normalized_auth_enabled not in {"1", "true", "yes", "on", "0", "false", "no", "off"}:
        raise RuntimeError("UI_AUTH_ENABLED must be true or false")
    AUTH_ENABLED = _normalized_auth_enabled in {"1", "true", "yes", "on"}
elif isinstance(_ui_auth_config, dict) and "enabled" in _ui_auth_config:
    if not isinstance(_ui_auth_config["enabled"], bool):
        raise RuntimeError("ui_auth.enabled in config.json must be true or false")
    AUTH_ENABLED = _ui_auth_config["enabled"]
else:
    # Backwards compatibility for existing configs containing only password_hash.
    AUTH_ENABLED = bool(AUTH_PASSWORD_HASH)

if AUTH_ENABLED and not AUTH_PASSWORD_HASH:
    raise RuntimeError("UI authentication is enabled, but no password hash is configured. Set UI_AUTH_PASSWORD_HASH or ui_auth.password_hash.")
ES_CONFIG = {
    "url": _saved_config.get("url", os.getenv("ES_URL", "http://localhost:9200")),
    "username": _saved_config.get("username", os.getenv("ES_USERNAME")),
    "password": _saved_config.get("password", os.getenv("ES_PASSWORD")),
    "api_key": _saved_config.get("api_key", os.getenv("ES_API_KEY")),
    "verify_ssl": _saved_config.get("verify_ssl", True),
    "ca_file": str(CA_CERT_FILE) if _saved_config.get("ca_file") and CA_CERT_FILE.exists() else None,
    "kibana_url": _saved_config.get("kibana_url", os.getenv("KIBANA_URL", "")),
    "kibana_api_key": _saved_config.get("kibana_api_key", os.getenv("KIBANA_API_KEY")),
}

HTTP_CLIENTS: dict[tuple[bool, str | None], httpx.AsyncClient] = {}


def get_http_client(config: dict) -> httpx.AsyncClient:
    verify_ssl = bool(config.get("verify_ssl", True))
    ca_file = config.get("ca_file") if verify_ssl else None
    key = (verify_ssl, ca_file)
    client = HTTP_CLIENTS.get(key)
    if client is None:
        verify: bool | ssl.SSLContext = (
            ssl.create_default_context(cafile=ca_file) if ca_file else verify_ssl
        )
        client = httpx.AsyncClient(
            verify=verify,
            timeout=ES_TIMEOUT,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
        HTTP_CLIENTS[key] = client
    return client


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    clients = list(HTTP_CLIENTS.values())
    HTTP_CLIENTS.clear()
    await asyncio.gather(*(client.aclose() for client in clients))


app = FastAPI(title="Elastic Desk", version="0.1.0", lifespan=lifespan)


def auth_session_valid(request: Request) -> bool:
    token = request.cookies.get(AUTH_COOKIE)
    expires_at = AUTH_SESSIONS.get(token or "")
    if expires_at is None:
        return False
    if expires_at <= time.time():
        AUTH_SESSIONS.pop(token or "", None)
        return False
    return True


def cookie_is_secure(request: Request) -> bool:
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
    return request.url.scheme == "https" or forwarded_proto == "https"


@app.middleware("http")
async def protect_ui_api(request: Request, call_next):
    path = request.url.path
    auth_public_paths = {"/api/auth/status", "/api/auth/login", "/api/auth/logout"}
    protected_path = path.startswith("/api/") or path in {"/docs", "/redoc", "/openapi.json"}
    if AUTH_ENABLED and protected_path and path not in auth_public_paths:
        if not auth_session_valid(request):
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
    response = await call_next(request)
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


class AuthLogin(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


@app.get("/api/auth/status")
def auth_status(request: Request):
    enabled = AUTH_ENABLED
    return {"enabled": enabled, "authenticated": not enabled or auth_session_valid(request)}


@app.post("/api/auth/login")
def auth_login(payload: AuthLogin, request: Request, response: Response):
    global AUTH_PASSWORD_HASH
    if not AUTH_ENABLED or not AUTH_PASSWORD_HASH:
        raise HTTPException(status_code=404, detail="UI authentication is not enabled")

    now = time.time()
    client_ip = request.client.host if request.client else "unknown"
    for address, stamps in list(AUTH_LOGIN_ATTEMPTS.items()):
        recent = [stamp for stamp in stamps if now - stamp < 300]
        if recent:
            AUTH_LOGIN_ATTEMPTS[address] = recent
        else:
            AUTH_LOGIN_ATTEMPTS.pop(address, None)
    attempts = [stamp for stamp in AUTH_LOGIN_ATTEMPTS.get(client_ip, []) if now - stamp < 300]
    AUTH_LOGIN_ATTEMPTS[client_ip] = attempts
    if len(attempts) >= 5:
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again in five minutes.")

    try:
        PASSWORD_HASHER.verify(AUTH_PASSWORD_HASH, payload.password)
    except VerifyMismatchError:
        attempts.append(now)
        AUTH_LOGIN_ATTEMPTS[client_ip] = attempts
        raise HTTPException(status_code=401, detail="Incorrect password")
    except VerificationError as exc:
        raise HTTPException(status_code=503, detail="UI authentication configuration is invalid") from exc

    AUTH_LOGIN_ATTEMPTS.pop(client_ip, None)
    if PASSWORD_HASHER.check_needs_rehash(AUTH_PASSWORD_HASH):
        AUTH_PASSWORD_HASH = PASSWORD_HASHER.hash(payload.password)
        if not AUTH_HASH_FROM_ENV:
            saved = load_config()
            auth_config = saved.get("ui_auth") if isinstance(saved.get("ui_auth"), dict) else {}
            auth_config.update({"enabled": True, "password_hash": AUTH_PASSWORD_HASH})
            saved["ui_auth"] = auth_config
            try:
                CONFIG_FILE.write_text(json.dumps(saved, ensure_ascii=False, indent=2) + "\n")
                CONFIG_FILE.chmod(0o600)
            except OSError:
                # A read-only config mount is normal in container deployments.
                pass

    token = secrets.token_urlsafe(32)
    AUTH_SESSIONS[token] = now + AUTH_SESSION_TTL
    response.set_cookie(
        AUTH_COOKIE,
        token,
        max_age=AUTH_SESSION_TTL,
        path="/",
        secure=cookie_is_secure(request),
        httponly=True,
        samesite="strict",
    )
    return {"ok": True}


@app.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    token = request.cookies.get(AUTH_COOKIE)
    if token:
        AUTH_SESSIONS.pop(token, None)
    response.delete_cookie(
        AUTH_COOKIE,
        path="/",
        secure=cookie_is_secure(request),
        httponly=True,
        samesite="strict",
    )
    return {"ok": True}


@app.get("/api/config")
def get_config():
    return {
        "url": ES_CONFIG["url"],
        "has_credentials": bool(ES_CONFIG.get("api_key") or ES_CONFIG.get("username")),
        "verify_ssl": ES_CONFIG.get("verify_ssl", True),
        "has_ca": bool(ES_CONFIG.get("ca_file") and Path(ES_CONFIG["ca_file"]).exists()),
        "saved": CONFIG_FILE.exists(),
    }


class ConnectionConfig(BaseModel):
    url: str = Field(min_length=1, max_length=2000)
    username: str | None = None
    password: str | None = None
    api_key: str | None = None
    verify_ssl: bool = True
    ca_cert: str | None = None
    remove_ca: bool = False


@app.post("/api/config")
async def save_config(payload: ConnectionConfig):
    global ES_CONFIG
    url = payload.url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="Адрес должен начинаться с http:// или https://")

    uploaded_ca = (payload.ca_cert or "").strip()
    if len(uploaded_ca) > 1_000_000:
        raise HTTPException(status_code=413, detail="CA-файл слишком большой (максимум 1 МБ)")
    if uploaded_ca and "-----BEGIN CERTIFICATE-----" not in uploaded_ca:
        raise HTTPException(status_code=422, detail="Не удалось распознать PEM-сертификат CA")

    candidate = {
        "url": url,
        "username": (payload.username or "").strip() or None,
        "password": payload.password or None,
        "api_key": (payload.api_key or "").strip() or None,
        "verify_ssl": payload.verify_ssl,
        "ca_file": None,
        "ui_auth": load_config().get("ui_auth"),
        "kibana_url": ES_CONFIG.get("kibana_url", ""),
        "kibana_api_key": ES_CONFIG.get("kibana_api_key"),
    }
    pending_ca = ROOT / ".ca-upload.pending"
    if uploaded_ca and not payload.remove_ca:
        pending_ca.write_text(uploaded_ca + "\n")
        candidate["ca_file"] = str(pending_ca)
    elif not payload.remove_ca and url == ES_CONFIG["url"]:
        candidate["ca_file"] = ES_CONFIG.get("ca_file")

    # Keep credentials only after they successfully connect to the cluster.
    try:
        await es_request("_cluster/health", config=candidate)
    except HTTPException:
        if uploaded_ca and not payload.remove_ca:
            pending_ca.unlink(missing_ok=True)
        raise
    if uploaded_ca and not payload.remove_ca:
        pending_ca.replace(CA_CERT_FILE)
        candidate["ca_file"] = str(CA_CERT_FILE)
    CONFIG_FILE.write_text(json.dumps(candidate, ensure_ascii=False, indent=2) + "\n")
    try:
        CONFIG_FILE.chmod(0o600)
    except OSError:
        pass
    ES_CONFIG = candidate
    return {"ok": True, "url": url}


class KibanaConfig(BaseModel):
    url: str = Field(max_length=2000)
    api_key: str | None = None
    use_cluster_auth: bool = True


@app.get("/api/kibana-config")
def get_kibana_config():
    return {
        "url": ES_CONFIG.get("kibana_url", ""),
        "has_api_key": bool(ES_CONFIG.get("kibana_api_key")),
        "use_cluster_auth": not bool(ES_CONFIG.get("kibana_api_key")),
    }


@app.post("/api/kibana-config")
def save_kibana_config(payload: KibanaConfig):
    url = payload.url.strip().rstrip("/")
    if url and not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="URL Kibana должен начинаться с http:// или https://")
    if payload.use_cluster_auth:
        api_key = None
    else:
        api_key = (payload.api_key or "").strip() or ES_CONFIG.get("kibana_api_key")

    saved = load_config()
    saved.update({"kibana_url": url, "kibana_api_key": api_key})
    CONFIG_FILE.write_text(json.dumps(saved, ensure_ascii=False, indent=2) + "\n")
    try:
        CONFIG_FILE.chmod(0o600)
    except OSError:
        pass
    ES_CONFIG["kibana_url"] = url
    ES_CONFIG["kibana_api_key"] = api_key
    return {"ok": True, "url": url}


async def es_request(path: str, *, method: str = "GET", body: dict | None = None, config: dict | None = None):
    config = config or ES_CONFIG
    es_url = config["url"].rstrip("/")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if config.get("api_key"):
        headers["Authorization"] = f"ApiKey {config['api_key']}"
    elif config.get("username"):
        raw = f"{config['username']}:{config.get('password') or ''}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()

    try:
        response = await get_http_client(config).request(
            method,
            f"{es_url}/{path.lstrip('/')}",
            headers=headers,
            json=body,
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        try:
            details = exc.response.json().get("error", exc.response.text)
        except (ValueError, AttributeError):
            details = exc.response.text or str(exc)
        raise HTTPException(status_code=502, detail=f"Elasticsearch: {details}") from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Не удалось подключиться к Elasticsearch ({es_url}): {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Elasticsearch вернул некорректный JSON") from exc


async def kibana_request(path: str):
    kibana_url = ES_CONFIG.get("kibana_url", "").rstrip("/")
    if not kibana_url:
        raise HTTPException(status_code=400, detail="Укажите URL Kibana для получения данных Fleet")
    headers = {"Accept": "application/json", "kbn-xsrf": "true"}
    api_key = ES_CONFIG.get("kibana_api_key") or ES_CONFIG.get("api_key")
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    elif ES_CONFIG.get("username"):
        raw = f"{ES_CONFIG['username']}:{ES_CONFIG.get('password') or ''}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    try:
        response = await get_http_client(ES_CONFIG).get(
            f"{kibana_url}/{path.lstrip('/')}", headers=headers
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        try:
            body = exc.response.json()
            details = body.get("message", body.get("error", str(exc)))
        except (ValueError, AttributeError):
            details = exc.response.text or str(exc)
        raise HTTPException(status_code=502, detail=f"Kibana: {details}") from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Не удалось подключиться к Kibana ({kibana_url}): {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Kibana вернула некорректный JSON") from exc


async def optional_api(call):
    try:
        return {"ok": True, "data": await call}
    except HTTPException as exc:
        return {"ok": False, "error": exc.detail}


async def kibana_all_agents():
    target_count = FLEET_AGENTS_LIMIT
    per_page = min(target_count, 10000)
    first_page = await kibana_request(
        f"api/fleet/agents?page=1&perPage={per_page}&showInactive=true&getStatusSummary=true"
    )
    items = list(first_page.get("items") or [])
    total = int(first_page.get("total") or len(items))
    target_count = min(total, target_count)
    seen_ids = {item.get("id") for item in items if isinstance(item, dict) and item.get("id")}
    page = 2
    while len(items) < target_count:
        response = await kibana_request(
            f"api/fleet/agents?page={page}&perPage={per_page}&showInactive=true&getStatusSummary=false"
        )
        page_items = response.get("items") or []
        fresh_items = [
            item for item in page_items
            if not isinstance(item, dict) or not item.get("id") or item["id"] not in seen_ids
        ]
        if not fresh_items:
            break
        items.extend(fresh_items)
        seen_ids.update(item["id"] for item in fresh_items if isinstance(item, dict) and item.get("id"))
        page += 1
    return {
        **first_page,
        "items": items[:target_count],
        "truncated": total > target_count,
        "agent_limit": FLEET_AGENTS_LIMIT,
    }


@app.get("/api/fleet")
async def fleet_overview():
    agents, policies = await asyncio.gather(
        optional_api(kibana_all_agents()),
        optional_api(kibana_request("api/fleet/agent_policies?perPage=100&full=true")),
    )
    return {"agents": agents, "policies": policies}


@app.get("/api/cluster")
async def cluster_health():
    return await es_request("_cluster/health")


@app.get("/api/nodes")
async def nodes():
    data = await es_request("_nodes/stats/os,jvm,process,indices,fs")
    node_attrs_response = await asyncio.gather(
        es_request("_cat/nodeattrs?format=json&h=node,attr,value&s=node"),
        return_exceptions=True,
    )
    node_attrs = {}
    if node_attrs_response and isinstance(node_attrs_response[0], list):
        for item in node_attrs_response[0]:
            if not isinstance(item, dict) or not item.get("node") or not item.get("attr"):
                continue
            node_attrs.setdefault(item["node"], {})[item["attr"]] = item.get("value")
    result = []
    for node_id, node in data.get("nodes", {}).items():
        os_stats = node.get("os", {})
        jvm = node.get("jvm", {}).get("mem", {})
        docs = node.get("indices", {}).get("docs", {}).get("count", 0)
        fs_total = node.get("fs", {}).get("total", {})
        disk_total_bytes = fs_total.get("total_in_bytes")
        disk_available_bytes = fs_total.get("available_in_bytes", fs_total.get("free_in_bytes"))
        disk_used_bytes = (
            max(0, disk_total_bytes - disk_available_bytes)
            if disk_total_bytes is not None and disk_available_bytes is not None
            else None
        )
        roles = node.get("roles")
        if roles is None:
            attributes = node.get("attributes", {})
            roles = [
                role for role in ("master", "data", "ingest")
                if str(attributes.get(role, "")).lower() == "true"
            ] or ["node"]
        elif not roles:
            roles = ["coordinating"]
        node_attributes = node_attrs.get(node.get("name", node_id), {})
        result.append({
            "id": node_id,
            "name": node.get("name", node_id[:8]),
            "host": node.get("host") or node.get("ip", "—"),
            "roles": roles,
            "attributes": node_attributes,
            "master": False,
            "cpu": os_stats.get("cpu", {}).get("percent"),
            "heap_used_percent": jvm.get("heap_used_percent"),
            "heap_used_bytes": jvm.get("heap_used_in_bytes"),
            "heap_max_bytes": jvm.get("heap_max_in_bytes"),
            "documents": docs,
            "version": node.get("version", "—"),
            "disk_total_gb": disk_total_bytes / 1_000_000_000 if disk_total_bytes is not None else None,
            "disk_available_gb": disk_available_bytes / 1_000_000_000 if disk_available_bytes is not None else None,
            "disk_used_gb": disk_used_bytes / 1_000_000_000 if disk_used_bytes is not None else None,
        })
    # The stats response does not identify the elected master. Read it from cluster state.
    try:
        master_id = await es_request("_cluster/state/master_node")
        master_id = master_id.get("master_node")
        for node in result:
            node["master"] = node["id"] == master_id
    except HTTPException:
        pass
    return result


@app.get("/api/indices")
async def indices():
    return await es_request("_cat/indices?format=json&bytes=b&h=health,status,index,pri,rep,docs.count,store.size")


@app.get("/api/shards")
async def shards():
    data = await es_request("_cat/shards?format=json&bytes=b&h=index,shard,prirep,state,store,node")
    result = []
    for shard in data:
        size_bytes = parse_store_bytes(shard.get("store"))
        result.append({
            "index": shard.get("index", "—"),
            "shard": shard.get("shard", "—"),
            "type": "primary" if shard.get("prirep") == "p" else "replica",
            "state": shard.get("state", "—"),
            "size_bytes": size_bytes,
            "size_gb": size_bytes / 1_000_000_000 if size_bytes is not None else None,
            "node": shard.get("node") or "—",
        })
    return result


class ShardMoveSelection(BaseModel):
    index: str = Field(min_length=1, max_length=255)
    shard: int = Field(ge=0)
    from_node: str = Field(min_length=1, max_length=255)


class ShardMoveRequest(BaseModel):
    target_node: str = Field(min_length=1, max_length=255)
    shards: list[ShardMoveSelection] = Field(min_length=1, max_length=100)


async def validate_shard_moves(payload: ShardMoveRequest) -> list[dict]:
    target_node = payload.target_node.strip()
    if not target_node:
        raise HTTPException(status_code=422, detail="Укажите целевую ноду")

    node_data, live_shards = await asyncio.gather(
        es_request("_nodes?filter_path=nodes.*.name"),
        es_request("_cat/shards?format=json&h=index,shard,state,node"),
    )
    live_nodes = {node.get("name") for node in node_data.get("nodes", {}).values()}
    if target_node not in live_nodes:
        raise HTTPException(status_code=409, detail="Целевая нода больше не доступна в кластере")

    live_allocations = {
        (item.get("index"), str(item.get("shard")), item.get("node"), item.get("state"))
        for item in live_shards
    }
    commands = []
    seen = set()
    for selection in payload.shards:
        index = selection.index.strip()
        from_node = selection.from_node.strip()
        identity = (index, selection.shard, from_node)
        if not index or not from_node:
            raise HTTPException(status_code=422, detail="Индекс и исходная нода обязательны")
        if identity in seen:
            raise HTTPException(status_code=422, detail="В запросе есть повторяющиеся шарды")
        seen.add(identity)
        if from_node == target_node:
            raise HTTPException(status_code=422, detail=f"Шард {index}[{selection.shard}] уже находится на целевой ноде")
        if (index, str(selection.shard), from_node, "STARTED") not in live_allocations:
            raise HTTPException(
                status_code=409,
                detail=f"Шард {index}[{selection.shard}] изменил состояние или больше не назначен на {from_node}; обновите данные",
            )
        commands.append({"move": {
            "index": index,
            "shard": selection.shard,
            "from_node": from_node,
            "to_node": target_node,
        }})
    return commands


@app.post("/api/shards/move/preview")
async def preview_shard_moves(payload: ShardMoveRequest):
    commands = await validate_shard_moves(payload)
    return await es_request(
        "_cluster/reroute?dry_run=true&explain=true&metric=none",
        method="POST",
        body={"commands": commands},
    )


@app.post("/api/shards/move/apply")
async def apply_shard_moves(payload: ShardMoveRequest):
    commands = await validate_shard_moves(payload)
    return await es_request(
        "_cluster/reroute?explain=true&metric=none",
        method="POST",
        body={"commands": commands},
    )


def parse_store_bytes(value) -> int | None:
    """Parse CAT shard sizes returned either as bytes or as a human-readable value."""
    if value is None:
        return None
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(b|bytes|kb|mb|gb|tb|pb)?\s*", str(value), re.IGNORECASE)
    if not match:
        return None
    amount = float(match.group(1))
    unit = (match.group(2) or "b").lower()
    power = {"b": 0, "bytes": 0, "kb": 1, "mb": 2, "gb": 3, "tb": 4, "pb": 5}[unit]
    return int(amount * (1024 ** power))


class SearchRequest(BaseModel):
    index: str = Field(min_length=1, max_length=255)
    field: str = Field(default="_all", min_length=1, max_length=255)
    value: str = Field(min_length=1, max_length=2000)
    size: int = Field(default=20, ge=1, le=100)


@app.post("/api/search")
async def search(payload: SearchRequest):
    index = quote(payload.index, safe="*,-_")
    field = payload.field.strip()
    query = {"query": {"match": {field: payload.value}}, "size": payload.size}
    return await es_request(f"{index}/_search", method="POST", body=query)


app.mount("/", StaticFiles(directory=ROOT / "static", html=True), name="static")
