"""tlbench serve [--host 127.0.0.1] [--port 8100]   run the targets
tlbench score submission.json [--json]           score a tool's results against cases.json"""
from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["serve"]:
        from .targets.bench_server import serve

        opts = dict(zip(args[1::2], args[2::2]))
        serve(host=opts.get("--host", "127.0.0.1"), port=int(opts.get("--port", "8100")))
        return 0
    if args[:1] == ["score"]:
        from .score import main as score_main

        return score_main(args[1:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
