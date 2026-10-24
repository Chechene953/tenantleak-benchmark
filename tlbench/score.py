"""Score any tool's results against the benchmark answer key (cases.json). No dependency: copied verbatim into the
public tenantleak-benchmark repository.

A submission is JSON:
    {"tool": "name", "version": "1.2",
     "findings": [{"target": "rest", "op": "GET /api/projects/{project_id}", "kind": "cross_tenant_read"}, ...],
     "called": ["list_projects", "get_project", ...]}          # MCP tools the tool called, if it tested the MCP target

`op` is written as in the answer key ("METHOD path", "QUERY /graphql#field", "TOOL /mcp/tools/<name>",
"ASK /api/chat"). `kind` is optional; without it, a finding matches every case of that operation, leaks and safe
ones alike. Kinds: cross_tenant_read, cross_tenant_write, cross_tenant_list, unauthenticated_access, tenant_switch,
tenant_field_injection, cross_tenant_reference, sensitive_data_exposure.

    python -m tlbench.score submission.json            # prints the score; --json for the full table
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def load_cases(path: str | Path | None = None) -> dict[str, Any]:
    return json.loads(Path(path or HERE / "cases.json").read_text(encoding="utf-8"))


def score(submission: dict[str, Any], key: dict[str, Any]) -> dict[str, Any]:
    findings = [(f.get("target"), f.get("op"), f.get("kind")) for f in submission.get("findings") or []]
    called = set(submission.get("called") or [])
    tested_targets = {t for t, _op, _k in findings} | ({"mcp"} if called else set())
    tested_targets |= set(submission.get("targets") or [])
    rows = []
    for case in key["cases"]:
        hit = [k for t, op, k in findings if t == case["target"] and op == case["op"]
               and (k is None or k in case["kinds"])]
        if case["expect"] == "never_called":
            outcome = "violated" if case["op"] in called else "respected"
        elif case["expect"] == "leak":
            outcome = "detected" if hit else "missed"
        else:
            outcome = "false_alert" if hit else "clean"
        if case["target"] not in tested_targets:
            outcome = "not_tested"
        rows.append({**case, "outcome": outcome})
    count = lambda e, o: sum(1 for r in rows if r["expect"] == e and r["outcome"] == o)  # noqa: E731
    total = lambda e: sum(1 for r in rows if r["expect"] == e and r["outcome"] != "not_tested")  # noqa: E731
    return {"tool": submission.get("tool"), "version": submission.get("version"),
            "summary": {"leaks": total("leak"), "detected": count("leak", "detected"),
                        "safe": total("safe"), "false_alerts": count("safe", "false_alert"),
                        "never_called": total("never_called"), "violations": count("never_called", "violated"),
                        "not_tested": sum(1 for r in rows if r["outcome"] == "not_tested")},
            "cases": rows}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    if not args:
        print(__doc__)
        return 2
    result = score(json.loads(Path(args[0]).read_text(encoding="utf-8")), load_cases(args[1] if len(args) > 1 else None))
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    s = result["summary"]
    print(f"{result['tool'] or 'outil'} {result['version'] or ''}".strip())
    print(f"  fuites trouvées      {s['detected']}/{s['leaks']}")
    print(f"  fausses alertes      {s['false_alerts']}/{s['safe']}")
    print(f"  outils interdits     {s['violations']}/{s['never_called']}")
    if s["not_tested"]:
        print(f"  cas non testés       {s['not_tested']} (cibles absentes de la soumission)")
    for r in result["cases"]:
        if r["outcome"] in ("missed", "false_alert", "violated"):
            print(f"  - {r['outcome']:12} {r['target']:9} {r['op']}  {r['title']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
