"""Command line interface (also used as a CI quality gate).

Exit codes: 0 clean, 1 findings at/above --fail-on, 2 bad input or internal error.
"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__, support_text
from .fixer import ALL_FIXES, DEFAULT_ONLY, FAILED, fix_paths
from .report import RENDERERS
from .rules import RULE_TITLES, SEVERITY_ORDER
from .scanner import scan_project


def _scan(a) -> int:
    try:
        result, cfg = scan_project(a.path, ignore_rules=a.ignore, exclude=a.exclude,
                                   min_severity=a.min_severity, use_config=not a.no_config)
    except (NotADirectoryError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 2
    report = RENDERERS[a.format](result)
    if a.output:
        try:
            with open(a.output, "w", encoding="utf-8") as fh:
                fh.write(report)
        except OSError as exc:
            print(f"Cannot write {a.output}: {exc.strerror or exc}", file=sys.stderr)
            return 2
    else:
        print(report)
    for err in result.errors:
        print(f"WARNING: could not analyse {err}", file=sys.stderr)
    fail_on = a.fail_on or cfg.get("fail_on", "high")
    return 1 if result.worst() >= SEVERITY_ORDER[fail_on] else 0


def _fix(a) -> int:
    only = [x.strip() for x in a.only.split(",") if x.strip()]
    bad = [x for x in only if x not in ALL_FIXES]
    if bad:
        print(f"Unknown fix(es): {', '.join(bad)}. Choose from {', '.join(ALL_FIXES)}",
              file=sys.stderr)
        return 2
    FAILED.clear()
    notes: list[str] = []
    changes = fix_paths(a.path, only=only, pin=a.pin, write=a.write, notes=notes)
    for _, diff in changes:
        print(diff)
    verb = "updated" if a.write else "would change (dry-run, use --write to apply)"
    print(f"{len(changes)} workflow file(s) {verb}.")
    for note in notes:
        print(f"NOTE: {note}", file=sys.stderr)
    if a.pin and FAILED:
        print("WARNING: could not resolve SHA for: " + ", ".join(sorted(set(FAILED))) +
              "\n  (offline, unknown ref, or GitHub rate limit - set GITHUB_TOKEN and retry)",
              file=sys.stderr)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pipelineguard", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a repository")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("-f", "--format", choices=RENDERERS, default="text")
    s.add_argument("-o", "--output", help="write report to file")
    s.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                   help="exit 1 if a finding at/above this severity exists (default: high)")
    s.add_argument("--min-severity", choices=list(SEVERITY_ORDER))
    s.add_argument("--ignore", action="append", default=[], metavar="RULE",
                   help="ignore a rule id (repeatable)")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="exclude paths matching a glob (repeatable)")
    s.add_argument("--no-config", action="store_true", help="ignore .pipelineguard.toml")

    f = sub.add_parser("fix", help="auto-fix workflows (dry-run unless --write)")
    f.add_argument("path", nargs="?", default=".")
    f.add_argument("--write", action="store_true", help="apply the changes")
    f.add_argument("--only", default=",".join(DEFAULT_ONLY),
                   help=f"comma list from: {', '.join(ALL_FIXES)}")
    f.add_argument("--pin", action="store_true",
                   help="also pin actions to commit SHAs (needs internet; set GITHUB_TOKEN)")

    sub.add_parser("rules", help="list all rules")
    sub.add_parser("about", help="show support / contact information")
    sub.add_parser("gui", help="launch the Tkinter desktop app")
    return p


def _run(argv: list[str] | None) -> int:
    a = _build_parser().parse_args(argv)
    if a.cmd == "scan":
        return _scan(a)
    if a.cmd == "fix":
        return _fix(a)
    if a.cmd == "rules":
        for rid, title in RULE_TITLES.items():
            print(f"{rid}  {title}")
    elif a.cmd == "about":
        print(f"PipelineGuard {__version__}\n{support_text()}")
    else:
        try:
            from .gui import main as gui_main
        except ImportError:
            print("The GUI needs Tkinter, which is not installed "
                  "(Debian/Ubuntu: apt install python3-tk).", file=sys.stderr)
            return 2
        gui_main()
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _run(argv)
    except BrokenPipeError:       # e.g. `pipelineguard scan | head`
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:      # never let a crash look like "findings found" (exit 1)
        if os.environ.get("PIPELINEGUARD_DEBUG"):
            raise
        print(f"pipelineguard: internal error: {type(exc).__name__}: {exc}\n"
              "  (set PIPELINEGUARD_DEBUG=1 for a traceback)", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
