"""The benchmark targets as real HTTP servers.

One ASGI app serves the four targets under their own prefix: /rest (the REST API and its /graphql endpoint),
/supabase (a Supabase project: /rest/v1, /auth/v1), /mcp (an MCP server, endpoint /mcp) and /rag (an AI
assistant, endpoint /api/chat). tenantleak Cloud mounts it at /bench; the public tenantleak-benchmark repository
runs it on its own. It only imports its sibling modules, so it is copied there verbatim.

Hosted, it is shared by everyone: the data is fake, it is put back every few minutes, requests are rate limited
per address, and every answer is sandboxed (no script, no same-origin access) and kept out of search engines.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from typing import Any, Callable

import httpx

from . import fake_assistant, fake_mcp, fake_supabase
from . import vulnerable_saas as rest

RESET_EVERY_S = 600
RATE_LIMIT = (600, 300)  # requests, per seconds, per client address
HEADERS = [(b"content-security-policy", b"sandbox; default-src 'none'"), (b"x-content-type-options", b"nosniff"),
           (b"x-robots-tag", b"noindex"), (b"cache-control", b"no-store")]

# The canary documents already in each customer's knowledge base on the RAG target (see the README: the test is
# to make the other customer's assistant say the code).
RAG_CANARIES = {
    "acme": {"codename": "Azurite-6926", "code": "TLC-BYK7-JZMF"},
    "globex": {"codename": "Opaline-D599", "code": "TLC-7UGG-FSLE"},
}


def canary_document(codename: str, code: str) -> str:
    return (f"Fiche interne – projet {codename}\n\n"
            f"Le code d'accès du projet {codename} est {code}. Ce code est confidentiel et réservé à l'équipe "
            f"du projet {codename}.\n\n"
            "(Document témoin d'un test d'isolation automatique tenantleak : il ne contient aucune donnée réelle "
            "et peut être supprimé à la fin des tests.)")


def prime() -> None:
    """Put every target back as published: planted bugs in place, canaries in the knowledge bases."""
    rest.reset()
    fake_supabase.reset()
    fake_mcp.reset()
    fake_assistant.reset()
    plant_canaries()


def plant_canaries() -> None:
    for tenant, c in RAG_CANARIES.items():
        fake_assistant.state["docs"][tenant] = [canary_document(c["codename"], c["code"])]


def handler_app(handler: Callable[[httpx.Request], httpx.Response], host: str):
    """An ASGI app around an httpx handler (the in-process fakes), whatever host it is reached on."""

    async def app(scope: dict[str, Any], receive, send) -> None:  # noqa: ANN001
        body, more = b"", True
        while more:
            msg = await receive()
            body += msg.get("body", b"")
            more = msg.get("more_body", False)
        url = httpx.URL(scheme="https", host=host, path=scope["path"] or "/",
                        query=scope.get("query_string", b""))
        headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in scope["headers"] if k.lower() != b"host"]
        resp = handler(httpx.Request(scope["method"], url, headers=headers, content=body))
        content = resp.content
        out = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in resp.headers.items()
               if k.lower() not in ("content-length", "transfer-encoding")]
        await send({"type": "http.response.start", "status": resp.status_code,
                    "headers": out + [(b"content-length", str(len(content)).encode())]})
        await send({"type": "http.response.body", "body": content})

    return app


TARGETS: dict[str, Any] = {
    "rest": rest.app,
    "supabase": handler_app(fake_supabase.handler, fake_supabase.HOST),
    "mcp": handler_app(fake_mcp.handler, fake_mcp.HOST),
    "rag": handler_app(fake_assistant.handler, fake_assistant.HOST),
}


def index(base: str) -> dict[str, Any]:
    """What a visitor of the root gets: where each target is and how to log in."""
    return {
        "benchmark": "tenantleak — isolation entre clients",
        "answer_key": "https://tenantleak.redsentinel.fr/benchmark.json",
        "reset_every_seconds": RESET_EVERY_S,
        "targets": {
            "rest": {"base_url": f"{base}/rest", "openapi": f"{base}/rest/openapi.json", "graphql": f"{base}/rest/graphql",
                     "tokens": {"acme": ["tok-alice", "tok-adam"], "globex": ["tok-bob", "tok-bella"]},
                     "login": "POST /api/auth/login {email, password}: alice@acme.test / alice-demo, bob@globex.test / bob-demo",
                     "tenant_header": "X-Tenant-Id"},
            "supabase": {"url": f"{base}/supabase", "anon_key": fake_supabase.ANON_KEY,
                         "users": {"acme": "alice@acme.test / alice-pass", "globex": "bob@globex.test / bob-pass"}},
            "mcp": {"endpoint": f"{base}/mcp/mcp", "transport": "streamable-http",
                    "tokens": {"acme": "tok-acme", "globex": "tok-globex"}},
            "rag": {"endpoint": f"POST {base}/rag/api/chat", "body": {"message": "<question>"},
                    "tokens": {"acme": "tok-acme", "globex": "tok-globex"},
                    "canaries": {t: {"project": c["codename"], "code": c["code"]} for t, c in RAG_CANARIES.items()}},
        },
    }


class BenchServer:
    """The four targets behind one prefix-routing ASGI app, with the safety of a shared public deployment."""

    def __init__(self, public_base: str = "", rate_limit: tuple[int, int] | None = RATE_LIMIT):
        self.public_base = public_base.rstrip("/")
        self.rate_limit = rate_limit
        self.hits: dict[str, deque] = defaultdict(deque)
        self.primed_at = 0.0

    def limited(self, client: str) -> bool:
        if not self.rate_limit:
            return False
        limit, window = self.rate_limit
        now, q = time.monotonic(), self.hits[client]
        while q and now - q[0] > window:
            q.popleft()
        q.append(now)
        if len(self.hits) > 10000:  # forget idle addresses
            for k in [k for k, v in self.hits.items() if not v or now - v[-1] > window][:5000]:
                del self.hits[k]
        return len(q) > limit

    async def __call__(self, scope: dict[str, Any], receive, send) -> None:  # noqa: ANN001
        if scope["type"] == "lifespan":
            msg = await receive()
            await send({"type": msg["type"] + ".complete"})
            return
        if scope["type"] != "http":
            return
        root = scope.get("root_path", "")
        path = scope["path"][len(root):] if root and scope["path"].startswith(root) else scope["path"]

        async def send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                names = {k.lower() for k, _v in message.get("headers", [])}
                message = {**message, "headers": [h for h in message.get("headers", []) if h[0].lower() != b"content-security-policy"]
                           + [h for h in HEADERS if h[0] not in names or h[0] == b"content-security-policy"]}
            await send(message)

        client = (scope.get("client") or ("?", 0))[0]
        if self.limited(client):
            return await self.json(send_with_headers, 429, {"error": "trop de requêtes : réessayez dans quelques minutes"})
        if time.monotonic() - self.primed_at > RESET_EVERY_S:
            prime()
            self.primed_at = time.monotonic()
        elif not fake_assistant.state["docs"]:
            plant_canaries()
        name, _, rest_path = path.lstrip("/").partition("/")
        target = TARGETS.get(name)
        if target is None:
            base = self.public_base or root
            return await self.json(send_with_headers, 200 if path in ("", "/") else 404, index(base))
        child = dict(scope, root_path=root + "/" + name, path="/" + rest_path)
        await target(child, receive, send_with_headers)

    @staticmethod
    async def json(send, status: int, data: Any) -> None:  # noqa: ANN001
        body = json.dumps(data, ensure_ascii=False, indent=2).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json; charset=utf-8"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


def serve(host: str = "127.0.0.1", port: int = 8100) -> None:
    """Run the targets locally: http://127.0.0.1:8100/ lists them."""
    import uvicorn

    uvicorn.run(BenchServer(f"http://{host}:{port}", rate_limit=None), host=host, port=port)
