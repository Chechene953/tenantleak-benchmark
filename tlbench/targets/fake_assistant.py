"""A fake RAG assistant, as a scan target in tests.

Two customers (tokens tok-acme and tok-globex) each add documents to their knowledge base. The leaky version
searches one shared index without a tenant filter (the classic RAG isolation bug); the fixed one filters by
customer. Answers stream as server-sent events cut into small pieces, so a code arrives split. A request may carry
a conversation_id: the assistant then remembers what was said in it. The leaky version trusts that identifier from
anyone; the fixed one (`fixed_history`) only lets the customer who started a conversation continue it. Use
`handler` with httpx.MockTransport.
"""
from __future__ import annotations

import json
import re

import httpx

HOST = "ai.acme-saas.fr"
URL = f"https://{HOST}"
PATH = "/api/chat"
TOKENS = {"tok-acme": "acme", "tok-globex": "globex"}
state: dict = {"docs": {}, "fixed": False, "questions": [], "conversations": {}, "fixed_history": False}


def reset() -> None:
    state["docs"], state["fixed"], state["questions"] = {}, False, []
    state["conversations"], state["fixed_history"] = {}, False


def _retrieve(tenant: str, question: str) -> list[str]:
    pool = [(t, d) for t, docs in state["docs"].items() for d in docs]
    if state["fixed"]:
        pool = [(t, d) for t, d in pool if t == tenant]
    words = {w for w in re.findall(r"[\w-]{5,}", question)}
    named = [d for _t, d in pool if any(w in d for w in words if "-" in w)]
    return named or ([d for _t, d in pool] if "codes" in question else [])


def handler(request: httpx.Request) -> httpx.Response:
    if request.url.host != HOST or request.url.path != PATH or request.method != "POST":
        return httpx.Response(404)
    tenant = TOKENS.get(request.headers.get("authorization", "").removeprefix("Bearer "))
    if tenant is None:
        return httpx.Response(401, json={"error": "login required"})
    body = json.loads(request.content or b"{}")
    question, conv_id = body.get("message", ""), body.get("conversation_id")
    state["questions"].append((tenant, question))
    history: list[str] = []
    if conv_id:
        conv = state["conversations"].setdefault(conv_id, {"tenant": tenant, "messages": []})
        if state["fixed_history"] and conv["tenant"] != tenant:
            return httpx.Response(404, json={"error": "conversation not found"})
        history = conv["messages"]
        history.append(question)
    if "Retiens ce code" in question:
        answer = "Noté : " + " ".join(re.findall(r"MEM-[A-Z0-9]{4}-[A-Z0-9]{4}", question))
    elif "retenir plus tôt" in question:
        remembered = [m for q in history for m in re.findall(r"MEM-[A-Z0-9]{4}-[A-Z0-9]{4}", q)]
        answer = ("Vous m'avez demandé de retenir " + ", ".join(remembered) + ".") if remembered else "Je ne sais pas."
    else:
        found = _retrieve(tenant, question)
        codes = [m.group(0) for d in found for m in re.finditer(r"TLC-[A-Z0-9]{4}-[A-Z0-9]{4}", d)]
        answer = ("Voici ce que j'ai trouvé : " + ", ".join(codes) + ".") if codes else "Je n'ai trouvé aucun document à ce sujet."
    chunks = [answer[i:i + 5] for i in range(0, len(answer), 5)]
    body = "".join(f"data: {json.dumps({'delta': c})}\n\n" for c in chunks) + "data: [DONE]\n\n"
    return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})
