"""CLI entry point."""

from __future__ import annotations

import argparse
import sys

from .report import render_console, render_json
from .scanner import Scanner


def main() -> None:
    p = argparse.ArgumentParser(
        prog="graphql-tester",
        description="GraphQL Security Tester — automated endpoint security checks",
    )
    p.add_argument("endpoint", help="GraphQL endpoint URL")
    p.add_argument("--auth", help="Authorization header value (e.g. 'Bearer TOKEN')")
    p.add_argument("--format", choices=["console", "json"], default="console")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--depth", type=int, default=15, help="Query depth to test (default: 15)")
    p.add_argument("--batch-size", type=int, default=50)
    p.add_argument("--output", help="Write report to file")
    args = p.parse_args()

    scanner = Scanner(
        endpoint=args.endpoint,
        auth_header=args.auth,
        depth=args.depth,
        batch_size=args.batch_size,
    )

    report = scanner.run()

    if args.format == "json":
        output = render_json(report)
    else:
        output = render_console(report, color=not args.no_color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Report saved to: {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output)

    sys.exit(1 if report.critical_count > 0 else 0)


if __name__ == "__main__":
    main()
