"""A fake MCP server (Streamable HTTP), as a scan target in tests.

Two customers, acme (token tok-acme) and globex (token tok-globex). `list_projects` and `get_invoice` check the
customer; `get_project` does not (the Asana-style leak); `delete_project` and `create_note` must never be called;
`search_documents` takes a free-text query and searches every customer's projects (fixed: only the caller's). Answers alternate between JSON and an event stream, and every call
must carry the session id given by `initialize`. Use `handler` with httpx.MockTransport.
"""
from __future__ import annotations

import itertools
import json

import httpx

HOST = "mcp.acme-ai.fr"
URL = f"https://{HOST}"
PATH = "/mcp"
TOKENS = {"tok-acme": "acme", "tok-globex": "globex"}
PROJECTS = [{"id": "p-1", "org": "acme", "name": "Refonte site", "budget": 48200, "owner": "claire@acme.test"},
            {"id": "p-2", "org": "globex", "name": "Audit interne", "budget": 91750, "owner": "marc@globex.test"}]
INVOICES = [{"id": "inv-1", "org": "acme", "amount": 12400, "client": "Durand SA"},
            {"id": "inv-2", "org": "globex", "amount": 8650, "client": "Martin SARL"}]
TOOLS = [
    {"name": "list_projects", "description": "Projects of your organisation",
     "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": True}},
    {"name": "get_project", "description": "One project",
     "inputSchema": {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}},
    {"name": "list_invoices", "inputSchema": {"type": "object", "properties": {"status": {"type": "string", "enum": ["all", "paid"]}},
                                              "required": ["status"]}},
    {"name": "get_invoice", "inputSchema": {"type": "object", "properties": {"invoice_id": {"type": "string"}},
                                            "required": ["invoice_id"]}, "annotations": {"readOnlyHint": True}},
    {"name": "search_documents", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}},
                                                 "required": ["query"]}},
    {"name": "delete_project", "inputSchema": {"type": "object", "properties": {"project_id": {"type": "string"}},
                                               "required": ["project_id"]}, "annotations": {"destructiveHint": True}},
    {"name": "create_note", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
    {"name": "get_status", "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": False}},
]
state: dict = {"sessions": {}, "calls": [], "fixed": False}
_ids = itertools.count(1)


def reset() -> None:
    state["sessions"], state["calls"], state["fixed"] = {}, [], False


def _answer(rpc_id, result=None, error=None, stream=False, headers=None) -> httpx.Response:
    msg = {"jsonrpc": "2.0", "id": rpc_id, **({"error": error} if error else {"result": result})}
    if stream:
        body = f"event: message\ndata: {json.dumps(msg)}\n\n"
        return httpx.Response(200, text=body, headers={"content-type": "text/event-stream", **(headers or {})})
    return httpx.Response(200, json=msg, headers=headers or {})


def _text(data) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(data)}]}


def handler(request: httpx.Request) -> httpx.Response:
    if request.url.host != HOST or request.url.path != PATH or request.method != "POST":
        return httpx.Response(404)
    org = TOKENS.get(request.headers.get("authorization", "").removeprefix("Bearer "))
    if org is None:
        return httpx.Response(401, json={"error": "invalid_token"})
    msg = json.loads(request.content or b"{}")
    method, rpc_id, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if method == "initialize":
        sid = f"s-{next(_ids)}"
        state["sessions"][sid] = org
        return _answer(rpc_id, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                                "serverInfo": {"name": "acme-ai", "version": "1"}}, headers={"mcp-session-id": sid})
    if state["sessions"].get(request.headers.get("mcp-session-id", "")) != org:
        return httpx.Response(400, json={"error": "missing or foreign session"})
    if method == "notifications/initialized":
        return httpx.Response(202)
    stream = rpc_id % 2 == 0
    if method == "tools/list":
        return _answer(rpc_id, {"tools": TOOLS}, stream=stream)
    if method != "tools/call":
        return _answer(rpc_id, error={"code": -32601, "message": "Method not found"})
    name, args = params.get("name"), params.get("arguments") or {}
    state["calls"].append((org, name))
    if name == "list_projects":
        return _answer(rpc_id, _text({"projects": [p for p in PROJECTS if p["org"] == org]}), stream=stream)
    if name == "get_project":
        p = next((p for p in PROJECTS if p["id"] == args.get("project_id")), None)
        if p is None or (state["fixed"] and p["org"] != org):
            return _answer(rpc_id, {"content": [{"type": "text", "text": f"Project {args.get('project_id')} not found"}],
                                    "isError": True}, stream=stream)
        return _answer(rpc_id, _text(p), stream=stream)
    if name == "list_invoices":
        return _answer(rpc_id, _text([i for i in INVOICES if i["org"] == org]), stream=stream)
    if name == "get_invoice":
        i = next((i for i in INVOICES if i["id"] == args.get("invoice_id") and i["org"] == org), None)
        if i is None:
            return _answer(rpc_id, {"content": [{"type": "text", "text": f"Invoice {args.get('invoice_id')} not found"}],
                                    "isError": True}, stream=stream)
        return _answer(rpc_id, {"structuredContent": i, "content": [{"type": "text", "text": json.dumps(i)}]}, stream=stream)
    if name == "search_documents":  # BUG: the search index is shared by every customer (fixed: filtered)
        q = str(args.get("query", "")).lower()
        hits = [p for p in PROJECTS if q and q in json.dumps(p).lower() and (not state["fixed"] or p["org"] == org)]
        return _answer(rpc_id, _text({"results": hits}), stream=stream)
    return _answer(rpc_id, {"content": [{"type": "text", "text": "done"}]}, stream=stream)
