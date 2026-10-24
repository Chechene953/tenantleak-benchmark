"""A fake Supabase project (GoTrue login + PostgREST tables + row level security), as a scan target in tests.

Two customers, acme (alice) and globex (bob). Some tables are protected properly, others are the classic mistakes:
`invoices` has no RLS at all (anyone with the public key reads everything), `documents` lets any logged-in user read
every row, `plans` is a public catalogue on purpose. Two functions: `org_projects(p_org_id)` is SECURITY DEFINER
without a membership check (fixed: "rpc"), `my_invoices()` filters on the caller. Storage: the private bucket
`attachments` keeps each user's files under its user id, but its policy lets any logged-in user list and download
them (fixed: "storage"); `avatars` is public on purpose. Use `handler` with httpx.MockTransport (sync or async).
"""
from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs

import httpx

HOST = "abcdefghijklmnop.supabase.co"
URL = f"https://{HOST}"


def _jwt(claims: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(claims)}.c2ln"


ANON_KEY = _jwt({"role": "anon", "ref": "abcdefghijklmnop"})
SERVICE_KEY = _jwt({"role": "service_role", "ref": "abcdefghijklmnop"})
USERS = {"alice@acme.test": ("alice-pass", "u-alice", "org-acme"), "bob@globex.test": ("bob-pass", "u-bob", "org-globex")}
ORG_OF = {uid: org for _pw, uid, org in USERS.values()}

TABLES = {
    "profiles": [{"id": "u-alice", "email": "alice@acme.test", "full_name": "Alice"},
                 {"id": "u-bob", "email": "bob@globex.test", "full_name": "Bob"}],
    "members": [{"id": 1, "user_id": "u-alice", "org_id": "org-acme", "role": "owner"},
                {"id": 2, "user_id": "u-bob", "org_id": "org-globex", "role": "owner"}],
    "projects": [{"id": "p-1", "org_id": "org-acme", "name": "Refonte site"},
                 {"id": "p-2", "org_id": "org-globex", "name": "Audit interne"}],
    "invoices": [{"id": "inv-1", "user_id": "u-alice", "amount": 1200, "customer": "Durand SA"},
                 {"id": "inv-2", "user_id": "u-bob", "amount": 860, "customer": "Martin SARL"}],
    "documents": [{"id": "doc-1", "owner_id": "u-alice", "title": "Contrat acme"},
                  {"id": "doc-2", "owner_id": "u-bob", "title": "Contrat globex"}],
    "plans": [{"id": "free", "price": 0}, {"id": "pro", "price": 49}],
}

FILES = {"attachments": ["u-alice/contrat-durand.pdf", "u-bob/devis-martin.pdf"],
         "avatars": ["u-alice/photo.png", "u-bob/photo.png"]}
BUCKETS = [{"id": "attachments", "name": "attachments", "public": False},
           {"id": "avatars", "name": "avatars", "public": True}]
RPCS = {"/rpc/org_projects": {"get": {"parameters": [{"name": "p_org_id", "in": "query", "required": True,
                                                      "type": "string"}]}},
        "/rpc/my_invoices": {"get": {"parameters": []}}}

state = {"verify_token": None, "fixed": set()}  # fixed: tables, "rpc" or "storage" whose policy was corrected


def policy(table: str, uid: str | None, row: dict) -> bool:
    """Row level security, as each table's policy (or its absence) says."""
    if table == "plans" or (table == "invoices" and "invoices" not in state["fixed"]):
        return True  # public on purpose / RLS disabled
    if uid is None:
        return False
    if table == "documents" and "documents" not in state["fixed"]:
        return True  # "authenticated users can read" policy, without an owner check
    if table == "profiles":
        return row["id"] == uid
    if table in ("members", "invoices"):
        return row["user_id"] == uid
    if table == "documents":
        return row["owner_id"] == uid
    if table == "projects":
        return row["org_id"] == ORG_OF.get(uid)
    return False


def reset() -> None:
    state["verify_token"], state["fixed"] = None, set()


def _uid(request: httpx.Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        part = auth[7:].split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))).get("sub")
    except (IndexError, ValueError):
        return None


def handler(request: httpx.Request) -> httpx.Response:
    if request.url.host != HOST:
        return httpx.Response(404)
    if request.headers.get("apikey") not in (ANON_KEY, SERVICE_KEY):
        return httpx.Response(401, json={"message": "No API key found in request"})
    path, uid = request.url.path, _uid(request)
    if path == "/auth/v1/token" and request.method == "POST":
        body = json.loads(request.content or b"{}")
        user = USERS.get(body.get("email", ""))
        if user is None or user[0] != body.get("password"):
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "Invalid login credentials"})
        token = _jwt({"sub": user[1], "role": "authenticated", "email": body["email"]})
        return httpx.Response(200, json={"access_token": token, "token_type": "bearer", "expires_in": 3600,
                                         "user": {"id": user[1]}})
    if path == "/auth/v1/user":
        return httpx.Response(200, json={"id": uid, "role": "authenticated"}) if uid else httpx.Response(401)
    if path == "/rest/v1/":
        pk = {"description": "Note:\nThis is a Primary Key.<pk/>", "type": "string"}
        return httpx.Response(200, json={
            "swagger": "2.0", "info": {"title": "standard public schema"},
            "paths": {"/": {}, **{f"/{t}": {"get": {}} for t in TABLES}, "/rpc/tenantleak_verification": {"post": {}},
                      **RPCS},
            "definitions": {t: {"properties": {"id": pk}} for t in TABLES}})
    if path == "/rest/v1/rpc/tenantleak_verification" and request.method == "POST":
        if not state["verify_token"]:
            return httpx.Response(404, json={"code": "PGRST202", "message": "Could not find the function"})
        return httpx.Response(200, json=state["verify_token"])
    query = parse_qs(request.url.query.decode() if isinstance(request.url.query, bytes) else str(request.url.query))
    if path == "/rest/v1/rpc/org_projects" and request.method == "GET":
        org = (query.get("p_org_id") or [""])[0]
        if "rpc" in state["fixed"] and ORG_OF.get(uid or "") != org:
            return httpx.Response(200, json=[])
        return httpx.Response(200, json=[r for r in TABLES["projects"] if r["org_id"] == org])  # BUG: no membership check
    if path == "/rest/v1/rpc/my_invoices" and request.method == "GET":
        return httpx.Response(200, json=[r for r in TABLES["invoices"] if uid and r["user_id"] == uid])
    if path == "/storage/v1/bucket" and request.method == "GET":
        return httpx.Response(200, json=BUCKETS if uid else [])
    if path.startswith("/storage/v1/object/list/") and request.method == "POST":
        bucket = path.rsplit("/", 1)[1]
        prefix = json.loads(request.content or b"{}").get("prefix", "")
        visible = [f for f in FILES.get(bucket, []) if _can_read(bucket, uid, f)]
        names, folders = [], []
        for f in visible:
            if not f.startswith(prefix):
                continue
            rest = f[len(prefix):]
            if "/" in rest:
                folder = rest.split("/")[0]
                if folder not in folders:
                    folders.append(folder)
                    names.append({"name": folder, "id": None, "metadata": None})
            else:
                names.append({"name": rest, "id": f"obj-{abs(hash(f)) % 10000}", "metadata": {"size": 10}})
        return httpx.Response(200, json=names)
    if path.startswith("/storage/v1/object/authenticated/") and request.method == "GET":
        bucket, _, name = path[len("/storage/v1/object/authenticated/"):].partition("/")
        if name in FILES.get(bucket, []) and _can_read(bucket, uid, name):
            return httpx.Response(200, content=b"%PDF-1.4 contenu", headers={"content-type": "application/pdf"})
        return httpx.Response(400, json={"statusCode": "404", "error": "not_found", "message": "Object not found"})
    if path.startswith("/rest/v1/") and request.method == "GET":
        table = path[len("/rest/v1/"):]
        if table not in TABLES:
            return httpx.Response(404, json={"code": "42P01"})
        rows = [r for r in TABLES[table] if policy(table, uid, r)]
        for col, values in query.items():
            if col in ("select", "limit", "order", "offset"):
                continue
            op, _, value = values[0].partition(".")
            if op == "eq":
                rows = [r for r in rows if str(r.get(col)) == value]
        limit = int((query.get("limit") or ["1000"])[0])
        return httpx.Response(200, json=rows[:limit])
    return httpx.Response(404)


def _can_read(bucket: str, uid: str | None, name: str) -> bool:
    if uid is None:
        return False
    if bucket == "avatars" or "storage" not in state["fixed"]:
        return True  # BUG on attachments: "authenticated users can read" without a folder check
    return name.split("/")[0] == uid
