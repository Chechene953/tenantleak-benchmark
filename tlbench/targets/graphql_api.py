"""GraphQL endpoint of the demo API (needs graphql-core). Bugs planted on purpose:

  project(id)    no tenant check                      (cross-tenant read)
  node(id)       Relay node lookup without any check  (invoice(id) is protected, node(id) leaks it anyway)
  me { apiKey }  the API key is returned in clear     (sensitive data exposure)
invoices (a Relay connection), invoice(id) and projects are correctly scoped to the caller's tenant.
"""
from __future__ import annotations

from typing import Any, Callable

SDL = """
interface Node { id: ID! }

type Project implements Node { id: ID! name: String! budget: Int tenantId: String! ownerId: String }
type Invoice implements Node { id: ID! amount: Int! customer: String! tenantId: String! }
type InvoiceEdge { node: Invoice! cursor: String! }
type InvoiceConnection { edges: [InvoiceEdge!]! totalCount: Int! }
type User { id: ID! email: String! name: String! role: String! apiKey: String }

type Query {
  me: User
  projects: [Project!]!
  project(id: ID!): Project
  invoices(first: Int): InvoiceConnection!
  invoice(id: ID!): Invoice
  node(id: ID!): Node
}
"""


def build(db: dict, fixed: set[str], user_for: Callable[[str | None], dict | None]
          ) -> Callable[[dict[str, Any], str | None], dict[str, Any]]:
    """Return execute(payload, bearer_token) -> GraphQL response dict."""
    from graphql import GraphQLError, build_schema, graphql_sync

    schema = build_schema(SDL)

    def project_view(p: dict) -> dict:
        return {"__typename": "Project", "id": p["id"], "name": p["name"], "budget": p["budget"],
                "tenantId": p["tenant_id"], "ownerId": p.get("owner_id")}

    def invoice_view(i: dict) -> dict:
        return {"__typename": "Invoice", "id": i["id"], "amount": i["amount"], "customer": i["customer"],
                "tenantId": i["tenant_id"]}

    def user_of(info) -> dict:
        user = info.context.get("user")
        if user is None:
            raise GraphQLError("authentication required", extensions={"code": "UNAUTHENTICATED"})
        return user

    def find(table: str, oid: str) -> dict | None:
        return next((row for row in db[table] if row["id"] == oid), None)

    def me(info):
        user = user_of(info)
        view = {k: user[k] for k in ("id", "email", "name", "role")}
        if "graphql_me" not in fixed:
            view["apiKey"] = user.get("api_key")  # BUG: secret returned in clear
        return view

    def projects(info):
        user = user_of(info)
        return [project_view(p) for p in db["projects"] if p["tenant_id"] == user["tenant"]]

    def project(info, id):  # noqa: A002 (GraphQL argument name)
        user = user_of(info)
        p = find("projects", id)
        if p is None or ("graphql_project" in fixed and p["tenant_id"] != user["tenant"]):
            raise GraphQLError("not found", extensions={"code": "NOT_FOUND"})
        return project_view(p)  # BUG: no tenant check

    def invoices(info, first=None):
        user = user_of(info)
        rows = [i for i in db["invoices"] if i["tenant_id"] == user["tenant"]][: first or None]
        return {"edges": [{"node": invoice_view(i), "cursor": i["id"]} for i in rows], "totalCount": len(rows)}

    def invoice(info, id):  # noqa: A002
        user = user_of(info)
        i = find("invoices", id)
        if i is None or i["tenant_id"] != user["tenant"]:
            raise GraphQLError("not found", extensions={"code": "NOT_FOUND"})
        return invoice_view(i)

    def node(info, id):  # noqa: A002
        user = user_of(info)
        for table, view in (("projects", project_view), ("invoices", invoice_view)):
            row = find(table, id)
            if row is not None:
                if "graphql_node" in fixed and row["tenant_id"] != user["tenant"]:
                    break
                return view(row)  # BUG: the generic node lookup forgets the tenant check
        raise GraphQLError("not found", extensions={"code": "NOT_FOUND"})

    schema.type_map["Node"].resolve_type = lambda value, info, typ: value.get("__typename")  # type: ignore[attr-defined]
    root = {"me": me, "projects": projects, "project": project, "invoices": invoices, "invoice": invoice, "node": node}

    def execute(payload: dict[str, Any], token: str | None) -> dict[str, Any]:
        query = payload.get("query")
        if not isinstance(query, str):
            return {"errors": [{"message": "missing query"}]}
        result = graphql_sync(schema, query, root_value=root, context_value={"user": user_for(token)},
                              variable_values=payload.get("variables"), operation_name=payload.get("operationName"))
        out: dict[str, Any] = {"data": result.data}
        if result.errors:
            out["errors"] = [e.formatted for e in result.errors]
        return out

    return execute
