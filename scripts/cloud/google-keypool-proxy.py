#!/usr/bin/env python3
import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

UPSTREAM_BASE = os.environ.get("GOOGLE_KEYPOOL_UPSTREAM_BASE", "https://generativelanguage.googleapis.com").rstrip("/")
BIND_HOST = os.environ.get("GOOGLE_KEYPOOL_BIND", "127.0.0.1")
BIND_PORT = int(os.environ.get("GOOGLE_KEYPOOL_PORT", "18889"))
STATE_FILE = os.environ.get("GOOGLE_KEYPOOL_STATE", "/home/ubuntu/.openclaw/google-keypool-state.json")
COOLDOWN_SECONDS = int(os.environ.get("GOOGLE_KEYPOOL_COOLDOWN_SECONDS", "86400"))
INVALID_KEY_COOLDOWN_SECONDS = int(os.environ.get("GOOGLE_KEY_INVALID_COOLDOWN_SECONDS", "604800"))
REQUEST_TIMEOUT_SECONDS = int(os.environ.get("GOOGLE_KEYPOOL_REQUEST_TIMEOUT_SECONDS", "180"))

LOCK = threading.Lock()
STATE = {"cursor": 0, "blocked_until": {}, "last_error": {}, "updated_at": 0}


def key_id(api_key: str) -> str:
    return hashlib.sha1(api_key.encode("utf-8", "ignore")).hexdigest()[:12]


def mask_key(api_key: str) -> str:
    if len(api_key) <= 10:
        return "***"
    return f"{api_key[:6]}...{api_key[-4:]}"


def load_keys() -> list[str]:
    keys = []
    raw = os.environ.get("GOOGLE_API_KEYS", "").strip()
    if raw:
        for part in raw.replace("\n", ",").split(","):
            v = part.strip()
            if v:
                keys.append(v)
    single = os.environ.get("GOOGLE_API_KEY", "").strip()
    if single:
        keys.append(single)
    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        v = os.environ.get(f"GOOGLE_API_KEY_{ch}", "").strip()
        if v:
            keys.append(v)
    for i in range(1, 33):
        v = os.environ.get(f"GOOGLE_API_KEY_{i}", "").strip()
        if v:
            keys.append(v)
        v2 = os.environ.get(f"GOOGLE_KEY_{i}", "").strip()
        if v2:
            keys.append(v2)
    out = []
    seen = set()
    for k in keys:
        if k in seen:
            continue
        seen.add(k)
        out.append(k)
    return out


def load_state() -> None:
    global STATE
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                STATE.update(
                    {
                        "cursor": int(data.get("cursor", 0)),
                        "blocked_until": dict(data.get("blocked_until", {})),
                        "last_error": dict(data.get("last_error", {})),
                        "updated_at": int(data.get("updated_at", 0)),
                    }
                )
    except Exception:
        pass


def save_state() -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = f"{STATE_FILE}.tmp"
    STATE["updated_at"] = int(time.time())
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(STATE, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_FILE)


class PoolExhausted(Exception):
    def __init__(self, next_unblock_ts: int):
        self.next_unblock_ts = next_unblock_ts
        super().__init__("all-google-keys-exhausted")


def choose_key() -> str:
    now = int(time.time())
    keys = load_keys()
    if not keys:
        raise RuntimeError("no-google-keys-configured")
    with LOCK:
        if STATE.get("updated_at", 0) == 0:
            load_state()
        blocked = STATE.get("blocked_until", {})
        available = [k for k in keys if int(blocked.get(key_id(k), 0)) <= now]
        if not available:
            next_ts = min(int(blocked.get(key_id(k), now + COOLDOWN_SECONDS)) for k in keys)
            raise PoolExhausted(next_ts)
        cursor = int(STATE.get("cursor", 0))
        idx = cursor % len(available)
        selected = available[idx]
        STATE["cursor"] = (cursor + 1) % max(len(available), 1)
        save_state()
        return selected


def classify_failure(status_code: int, body_text: str) -> str:
    low = (body_text or "").lower()
    if status_code == 429:
        return "quota"
    if status_code == 403 and ("quota" in low or "resource_exhausted" in low or "rate" in low):
        return "quota"
    if "resource_exhausted" in low or "quota exceeded" in low or "too many requests" in low:
        return "quota"
    if status_code in (400, 401, 403) and (
        "api key not valid" in low
        or "api key invalid" in low
        or "reported as leaked" in low
        or "permission_denied" in low
        or "credentials" in low
    ):
        return "invalid-key"
    return ""


def mark_key_exhausted(api_key: str, status_code: int, body_text: str, retry_after: str, reason: str) -> None:
    now = int(time.time())
    cooldown = COOLDOWN_SECONDS if reason == "quota" else INVALID_KEY_COOLDOWN_SECONDS
    block_until = now + cooldown
    try:
        if retry_after and retry_after.isdigit():
            block_until = max(block_until, now + int(retry_after))
    except Exception:
        pass
    kid = key_id(api_key)
    with LOCK:
        STATE.setdefault("blocked_until", {})[kid] = block_until
        STATE.setdefault("last_error", {})[kid] = {
            "ts": now,
            "status": status_code,
            "reason": reason,
            "message": (body_text or "")[:500],
        }
        save_state()


def build_target_url(raw_path: str, selected_key: str) -> str:
    parts = urlsplit(raw_path)
    qs = [(k, v) for (k, v) in parse_qsl(parts.query, keep_blank_values=True) if k.lower() != "key"]
    qs.append(("key", selected_key))
    query = urlencode(qs)
    path = parts.path or "/"
    return urlunsplit(("https", "generativelanguage.googleapis.com", path, query, ""))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _write_json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _status(self) -> None:
        keys = load_keys()
        now = int(time.time())
        blocked = STATE.get("blocked_until", {})
        last_error = STATE.get("last_error", {})
        rows = []
        for k in keys:
            kid = key_id(k)
            bu = int(blocked.get(kid, 0))
            rows.append(
                {
                    "id": kid,
                    "key": mask_key(k),
                    "blocked": bu > now,
                    "blocked_until": bu,
                    "last_error": last_error.get(kid),
                }
            )
        self._write_json(
            200,
            {
                "ok": True,
                "provider": "google-keypool-proxy",
                "upstream": UPSTREAM_BASE,
                "bind": f"{BIND_HOST}:{BIND_PORT}",
                "cooldownSeconds": COOLDOWN_SECONDS,
                "invalidKeyCooldownSeconds": INVALID_KEY_COOLDOWN_SECONDS,
                "keys": rows,
            },
        )

    def _proxy(self) -> None:
        if self.path.startswith("/__keypool/status"):
            self._status()
            return

        try:
            selected = choose_key()
        except PoolExhausted as ex:
            self._write_json(
                429,
                {
                    "error": {
                        "code": "google-keypool-exhausted",
                        "message": "Google 模型額度已用盡，所有 key 都在冷卻中。",
                        "nextRetryAtEpoch": ex.next_unblock_ts,
                    }
                },
            )
            return
        except RuntimeError as ex:
            self._write_json(500, {"error": {"code": "google-keypool-misconfigured", "message": str(ex)}})
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        payload = self.rfile.read(length) if length > 0 else None
        target_url = build_target_url(self.path, selected)
        headers = {}
        for k, v in self.headers.items():
            lk = k.lower()
            if lk in ("host", "content-length", "connection", "x-goog-api-key", "authorization"):
                continue
            headers[k] = v

        req = Request(target_url, data=payload, headers=headers, method=self.command)
        status = 502
        body = b""
        resp_headers = {}
        try:
            with urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                status = int(resp.status)
                body = resp.read()
                resp_headers = dict(resp.headers.items())
        except HTTPError as ex:
            status = int(ex.code)
            body = ex.read() if ex.fp is not None else b""
            resp_headers = dict(ex.headers.items()) if ex.headers else {}
        except URLError as ex:
            self._write_json(502, {"error": {"code": "google-upstream-unreachable", "message": str(ex.reason)}})
            return
        except Exception as ex:
            self._write_json(502, {"error": {"code": "google-upstream-error", "message": str(ex)}})
            return

        body_text = ""
        try:
            body_text = body.decode("utf-8", errors="ignore")
        except Exception:
            body_text = ""
        reason = classify_failure(status, body_text)
        if reason:
            mark_key_exhausted(selected, status, body_text, resp_headers.get("Retry-After", ""), reason)

        self.send_response(status)
        for k, v in resp_headers.items():
            lk = k.lower()
            if lk in ("content-length", "transfer-encoding", "connection"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Google-KeyPool", "enabled")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self._proxy()

    def do_POST(self):
        self._proxy()

    def do_PUT(self):
        self._proxy()

    def do_PATCH(self):
        self._proxy()

    def do_DELETE(self):
        self._proxy()

    def log_message(self, fmt: str, *args):
        # Keep systemd logs concise.
        return


def main() -> None:
    load_state()
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
