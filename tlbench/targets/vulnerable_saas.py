"""A deliberately vulnerable multi-tenant API, to try tenantleak safely.

    pip install fastapi uvicorn
    uvicorn examples.vulnerable_saas.app:app --port 8000
    # spec: http://localhost:8000/openapi.json

Two tenants (acme, globex), each with an admin and a member. Bugs planted on purpose:
  GET   /api/projects/{project_id}           no tenant check            (cross-tenant read)
  PATCH /api/projects/{project_id}           no tenant check            (cross-tenant write)
  GET   /api/users/{user_id}                 no tenant check            (cross-tenant read, PII)
  GET   /api/reports/{report_id}/export      no authentication at all   (unauthenticated + cross-tenant)
  GET   /api/search?tenant_id=               trusts the tenant_id param (cross-tenant read via query)
  GET   /api/admin/audit-logs                no role check              (members read admin data)
  GET   /api/contracts/{contract_id}         no tenant check, and no list endpoint: only reachable through
                                             the contract_id that project details reference
  GET   /api/workspace/settings              trusts the X-Tenant-Id header (tenant switch)
  GET   /api/workspace/members               trusts the X-Tenant-Id header (tenant switch on a listing)
  PATCH /api/notes/{note_id}                 accepts tenant_id in the body (mass assignment: move a note
                                             into another tenant)
  POST  /api/comments                        accepts a project_id of another tenant (cross-tenant reference:
                                             comment on someone else's project)
  GET   /api/me                              returns the user's API key in clear (sensitive data exposure)
Bearer tokens are either the static tok-… values or JWTs (HS256, see make_jwt); JWTs whose header says
"alg": "none" are accepted without any signature (forged tokens).
POST /graphql serves the same data through GraphQL (needs graphql-core), with its own planted bugs: see
graphql_api.py.
POST /api/auth/login exchanges an e-mail and password for a bearer token (passwords: <name>-demo).
Everything else is correctly protected.
"""
from __future__ import annotations

import base64
import copy
import os
import hashlib
import hmac
import json

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

try:  # the GraphQL endpoint is optional: pip install graphql-core
    from . import graphql_api
except ImportError:  # pragma: no cover - also covers running the file outside its package
    try:
        import graphql_api  # type: ignore[no-redef]
    except ImportError:
        graphql_api = None  # type: ignore[assignment]

TOKENS = {
    "tok-alice": {"id": "u-alice", "tenant": "acme", "role": "admin", "email": "alice@acme.test", "name": "Alice Martin",
                  "api_key": "sk_demo_acme_alice_7f3a9c"},
    "tok-adam": {"id": "u-adam", "tenant": "acme", "role": "member", "email": "adam@acme.test", "name": "Adam Roux",
                 "api_key": "sk_demo_acme_adam_51be20"},
    "tok-bob": {"id": "u-bob", "tenant": "globex", "role": "admin", "email": "bob@globex.test", "name": "Bob Leroy",
                "api_key": "sk_demo_globex_bob_c09d44"},
    "tok-bella": {"id": "u-bella", "tenant": "globex", "role": "member", "email": "bella@globex.test", "name": "Bella Durand",
                  "api_key": "sk_demo_globex_bella_88e1f2"},
}

SEED = {
    "projects": [
        {"id": "p-acme-1", "tenant_id": "acme", "name": "Acme Roadmap 2027", "budget": 120000, "owner_id": "u-alice",
         "contract_id": "c-acme-1"},
        {"id": "p-acme-2", "tenant_id": "acme", "name": "Acme Security Review", "budget": 45000, "owner_id": "u-adam"},
        {"id": "p-glx-1", "tenant_id": "globex", "name": "Globex Merger Plan", "budget": 980000, "owner_id": "u-bob",
         "contract_id": "c-glx-1"},
        {"id": "p-glx-2", "tenant_id": "globex", "name": "Globex Hiring Freeze", "budget": 0, "owner_id": "u-bella"},
    ],
    "documents": [
        {"id": "d-acme-1", "project_id": "p-acme-1", "tenant_id": "acme", "title": "Board minutes Q3 Acme.pdf"},
        {"id": "d-acme-2", "project_id": "p-acme-2", "tenant_id": "acme", "title": "Acme pentest scope.docx"},
        {"id": "d-glx-1", "project_id": "p-glx-1", "tenant_id": "globex", "title": "Globex term sheet draft.pdf"},
    ],
    "invoices": [
        {"id": "inv-acme-1", "tenant_id": "acme", "amount": 4200, "customer": "Acme Industries SAS"},
        {"id": "inv-glx-1", "tenant_id": "globex", "amount": 18750, "customer": "Globex Corporation Ltd"},
    ],
    "reports": [
        {"id": "r-acme-1", "tenant_id": "acme", "title": "Acme quarterly revenue 2026", "revenue": 3400000},
        {"id": "r-glx-1", "tenant_id": "globex", "title": "Globex quarterly revenue 2026", "revenue": 12900000},
    ],
    "contracts": [
        {"id": "c-acme-1", "tenant_id": "acme", "title": "Acme master services agreement", "value": 250000},
        {"id": "c-glx-1", "tenant_id": "globex", "title": "Globex reseller contract", "value": 1750000},
    ],
    "settings": {
        "acme": {"tenant_id": "acme", "sso_domain": "acme.test", "billing_email": "finance@acme.test", "plan": "enterprise"},
        "globex": {"tenant_id": "globex", "sso_domain": "globex.test", "billing_email": "ap@globex.test", "plan": "growth"},
    },
    "notes": [
        {"id": "n-acme-1", "tenant_id": "acme", "text": "Acme renewal call on Friday"},
        {"id": "n-glx-1", "tenant_id": "globex", "text": "Globex churn risk: CFO unhappy"},
    ],
    "comments": [],
    "tasks": [],
    "audit_logs": [
        {"id": "log-acme-1", "tenant_id": "acme", "event": "admin exported all customer emails", "actor": "u-alice"},
        {"id": "log-glx-1", "tenant_id": "globex", "event": "admin rotated the billing API key", "actor": "u-bob"},
    ],
}

DB = copy.deepcopy(SEED)
# names of bugs "fixed", to simulate a remediation (tests, or DEMO_FIXED=get_project,get_contract,tenant_header,jwt_none,me,create_comment)
FIXED: set[str] = {name for name in os.environ.get("DEMO_FIXED", "").split(",") if name}
bearer = HTTPBearer(auto_error=False)
app = FastAPI(title="Vulnerable SaaS (tenantleak demo)", version="1.0.0")


def reset() -> None:
    DB.clear()
    DB.update(copy.deepcopy(SEED))
    FIXED.clear()


JWT_SECRET = b"demo-only-secret-never-use-in-production"


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_jwt(user_id: str) -> str:
    """A valid HS256 token for a demo user (its subject is the user id, e.g. u-bella)."""
    head = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64e(json.dumps({"sub": user_id, "iss": "vulnerable-saas"}).encode())
    sig = _b64e(hmac.new(JWT_SECRET, f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


def _jwt_user(token: str) -> dict | None:
    try:
        head, body, sig = token.split(".")
        header, payload = json.loads(_b64d(head)), json.loads(_b64d(body))
    except (ValueError, TypeError):
        return None
    alg = str(header.get("alg", ""))
    if alg == "HS256":
        expected = _b64e(hmac.new(JWT_SECRET, f"{head}.{body}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig):
            return None
    elif not (alg.lower() == "none" and "jwt_none" not in FIXED):  # BUG: unsigned tokens are accepted
        return None
    return next((u for u in TOKENS.values() if u["id"] == payload.get("sub")), None)


def user_for(token: str | None) -> dict | None:
    if not token:
        return None
    if token in TOKENS:
        return TOKENS[token]
    return _jwt_user(token) if token.count(".") == 2 else None


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    user = user_for(creds.credentials if creds else None)
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


def require_admin(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    return user


def _get(table: str, oid: str) -> dict:
    for row in DB[table]:
        if row["id"] == oid:
            return row
    raise HTTPException(status_code=404, detail="not found")


def _owned(table: str, oid: str, user: dict) -> dict:
    row = _get(table, oid)
    if row["tenant_id"] != user["tenant"]:
        raise HTTPException(status_code=404, detail="not found")
    return row


class ProjectUpdate(BaseModel):
    name: str | None = None
    budget: int | None = None


class UserCreate(BaseModel):
    email: str
    role: str = "member"


class Login(BaseModel):
    email: str
    password: str


class NoteUpdate(BaseModel):
    text: str | None = None
    tenant_id: str | None = None


class CommentCreate(BaseModel):
    project_id: str
    text: str


class TaskCreate(BaseModel):
    document_id: str
    title: str


@app.post("/api/auth/login", openapi_extra={"security": []})
def login(body: Login):
    for token, user in TOKENS.items():
        if user["email"] == body.email and body.password == user["id"].removeprefix("u-") + "-demo":
            return {"access_token": token, "token_type": "bearer", "expires_in": 3600}
    raise HTTPException(status_code=401, detail="invalid credentials")


@app.get("/api/health", openapi_extra={"security": []})
def health():
    return {"status": "ok"}


@app.get("/api/me")
def me(user: dict = Depends(current_user)):
    if "me" in FIXED:
        return {k: v for k, v in user.items() if k != "api_key"}
    return user  # BUG: the API key is returned in clear


@app.get("/api/projects")
def list_projects(user: dict = Depends(current_user)):
    return {"data": [p for p in DB["projects"] if p["tenant_id"] == user["tenant"]]}


@app.get("/api/projects/{project_id}")
def get_project(project_id: str, user: dict = Depends(current_user)):
    if "get_project" in FIXED:
        return _owned("projects", project_id, user)
    return _get("projects", project_id)  # BUG: no tenant check


@app.patch("/api/projects/{project_id}")
def update_project(project_id: str, body: ProjectUpdate, user: dict = Depends(current_user)):
    project = _get("projects", project_id)  # BUG: no tenant check
    project.update({k: v for k, v in body.model_dump().items() if v is not None})
    return project


@app.get("/api/projects/{project_id}/documents")
def list_documents(project_id: str, user: dict = Depends(current_user)):
    _owned("projects", project_id, user)
    return [d for d in DB["documents"] if d["project_id"] == project_id]


@app.get("/api/projects/{project_id}/documents/{document_id}")
def get_document(project_id: str, document_id: str, user: dict = Depends(current_user)):
    _owned("projects", project_id, user)
    doc = _owned("documents", document_id, user)
    if doc["project_id"] != project_id:
        raise HTTPException(status_code=404, detail="not found")
    return doc


@app.delete("/api/documents/{document_id}", status_code=204)
def delete_document(document_id: str, user: dict = Depends(current_user)):
    doc = _owned("documents", document_id, user)
    DB["documents"].remove(doc)


@app.get("/api/users")
def list_users(user: dict = Depends(current_user)):
    return [
        {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"], "tenant_id": u["tenant"]}
        for u in TOKENS.values() if u["tenant"] == user["tenant"]
    ]


@app.get("/api/users/{user_id}")
def get_user(user_id: str, user: dict = Depends(current_user)):
    for u in TOKENS.values():  # BUG: no tenant check
        if u["id"] == user_id:
            return {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"], "tenant_id": u["tenant"]}
    raise HTTPException(status_code=404, detail="not found")


@app.get("/api/invoices")
def list_invoices(user: dict = Depends(current_user)):
    return {"items": [i for i in DB["invoices"] if i["tenant_id"] == user["tenant"]]}


@app.get("/api/invoices/{invoice_id}")
def get_invoice(invoice_id: str, user: dict = Depends(current_user)):
    return _owned("invoices", invoice_id, user)


@app.get("/api/reports")
def list_reports(user: dict = Depends(current_user)):
    return [r for r in DB["reports"] if r["tenant_id"] == user["tenant"]]


@app.get("/api/reports/{report_id}/export")
def export_report(report_id: str):
    return _get("reports", report_id)  # BUG: no authentication, no tenant check


@app.get("/api/search")
def search(tenant_id: str = Query(...), q: str | None = None, user: dict = Depends(current_user)):
    rows = [p for p in DB["projects"] if p["tenant_id"] == tenant_id]  # BUG: trusts tenant_id
    if q:
        rows = [p for p in rows if q.lower() in p["name"].lower()]
    return rows


@app.get("/api/admin/audit-logs")
def audit_logs(user: dict = Depends(current_user)):
    return [log for log in DB["audit_logs"] if log["tenant_id"] == user["tenant"]]  # BUG: no role check


@app.get("/api/contracts/{contract_id}")
def get_contract(contract_id: str, user: dict = Depends(current_user)):
    if "get_contract" in FIXED:
        return _owned("contracts", contract_id, user)
    return _get("contracts", contract_id)  # BUG: no tenant check (and no list endpoint)


def _active_tenant(user: dict, x_tenant_id: str | None) -> str:
    if "tenant_header" in FIXED:
        return user["tenant"]
    return x_tenant_id or user["tenant"]  # BUG: trusts the header without checking membership


@app.get("/api/workspace/settings")
def workspace_settings(user: dict = Depends(current_user), x_tenant_id: str | None = Header(default=None)):
    return DB["settings"][_active_tenant(user, x_tenant_id)] if _active_tenant(user, x_tenant_id) in DB["settings"] else {}


@app.get("/api/workspace/members")
def workspace_members(user: dict = Depends(current_user), x_tenant_id: str | None = Header(default=None)):
    tenant = _active_tenant(user, x_tenant_id)
    return [{"id": u["id"], "email": u["email"], "role": u["role"]} for u in TOKENS.values() if u["tenant"] == tenant]


@app.get("/api/notes")
def list_notes(user: dict = Depends(current_user)):
    return [n for n in DB["notes"] if n["tenant_id"] == user["tenant"]]


@app.get("/api/notes/{note_id}")
def get_note(note_id: str, user: dict = Depends(current_user)):
    return _owned("notes", note_id, user)


@app.patch("/api/notes/{note_id}")
def update_note(note_id: str, body: NoteUpdate, user: dict = Depends(current_user)):
    note = _owned("notes", note_id, user)
    note.update({k: v for k, v in body.model_dump().items() if v is not None})  # BUG: tenant_id is writable
    return note


@app.get("/api/comments")
def list_comments(user: dict = Depends(current_user)):
    return [c for c in DB["comments"] if c["tenant_id"] == user["tenant"]]


@app.post("/api/comments", status_code=201)
def create_comment(body: CommentCreate, user: dict = Depends(current_user)):
    if "create_comment" in FIXED:
        _owned("projects", body.project_id, user)
    else:
        _get("projects", body.project_id)  # BUG: the project may belong to another tenant
    comment = {"id": f"cm-{len(DB['comments']) + 1}-{user['tenant']}", "tenant_id": user["tenant"],
               "project_id": body.project_id, "text": body.text, "author_id": user["id"]}
    DB["comments"].append(comment)
    return comment


@app.delete("/api/comments/{comment_id}", status_code=204)
def delete_comment(comment_id: str, user: dict = Depends(current_user)):
    DB["comments"].remove(_owned("comments", comment_id, user))


@app.post("/api/tasks", status_code=201)
def create_task(body: TaskCreate, user: dict = Depends(current_user)):
    _owned("documents", body.document_id, user)  # correct: the document must belong to the caller's tenant
    task = {"id": f"t-{len(DB['tasks']) + 1}-{user['tenant']}", "tenant_id": user["tenant"],
            "document_id": body.document_id, "title": body.title}
    DB["tasks"].append(task)
    return task


@app.delete("/api/tasks/{task_id}", status_code=204)
def delete_task(task_id: str, user: dict = Depends(current_user)):
    DB["tasks"].remove(_owned("tasks", task_id, user))


_graphql = None


@app.post("/graphql", include_in_schema=False)
def graphql_endpoint(payload: dict = Body(...), creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    global _graphql
    try:
        if _graphql is None:
            _graphql = graphql_api.build(DB, FIXED, user_for)
    except (AttributeError, ImportError):
        raise HTTPException(status_code=501, detail="GraphQL demo needs graphql-core") from None
    return _graphql(payload, creds.credentials if creds else None)


@app.post("/api/admin/users", status_code=201)
def create_user(body: UserCreate, user: dict = Depends(require_admin)):
    return {"id": "u-new", "email": body.email, "role": body.role, "tenant_id": user["tenant"]}
