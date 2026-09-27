"""Safe read-only CLI: operates only on an explicitly supplied OS5 snapshot file."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

FORBIDDEN_PREFIXES = ("/proc", "/sys", "/dev", "/etc", "/bin", "/sbin",
                      "/boot", "/lib", "/var")
FORBIDDEN_WIN = ("c:\\windows", "c:\\program files", "c:\\programdata")


def _is_forbidden(path: str) -> bool:
    def _check(p_str: str) -> bool:
        low = p_str.replace("\\", "/").lower()
        if low in ("/", "/proc", "/sys", "/dev"):
            return True
        for prefix in FORBIDDEN_PREFIXES:
            if low == prefix or low.startswith(prefix + "/"):
                return True
        no_colon = low.replace("/", "\\")
        for prefix in FORBIDDEN_WIN:
            if no_colon == prefix or no_colon.startswith(prefix + "\\"):
                return True
        return False

    if _check(path):
        return True
    try:
        resolved = str(Path(path).resolve())
        if _check(resolved):
            return True
    except Exception:
        pass
    return False


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="os5", description="OS5 fragment analyzer (read-only)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    an = sub.add_parser("analyze", help="analyze an OS5 snapshot JSON file")
    an.add_argument("snapshot", help="explicit path to OS5 snapshot JSON file")
    an.add_argument("--memory", action="store_true", help="analyze memory layout and fragmentation")
    an.add_argument("--processes", action="store_true", help="analyze processes and threads")
    an.add_argument("--objects", action="store_true", help="analyze kernel objects and refcounts")
    an.add_argument("--ipc", action="store_true", help="analyze IPC endpoints and queues")
    an.add_argument("--resources", action="store_true", help="analyze resource ownership")
    an.add_argument("--strict", action="store_true", help="exit with status 1 if any consistency error occurs")
    an.add_argument("--json", action="store_true", help="output full analysis as JSON")
    an.add_argument("--diagnostics", action="store_true", help="output only diagnostics as JSON")
    an.add_argument("--output", default=None, help="write analysis output to a destination file")
    return ap


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "analyze":
        spath = args.snapshot
        if _is_forbidden(spath):
            print(f"error: refusing to inspect host scope '{spath}'", file=sys.stderr)
            return 2
        p = Path(spath)
        if not p.is_file():
            print(f"error: snapshot file not found: {spath}", file=sys.stderr)
            return 2
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"error: invalid snapshot JSON: {exc}", file=sys.stderr)
            return 2
        from os5.fragment.analyzer import AnalyzerConfig, FragmentAnalyzer
        has_module_flags = any([args.memory, args.processes, args.objects, args.ipc, args.resources])
        if has_module_flags:
            cfg = AnalyzerConfig(
                include_memory=bool(args.memory),
                include_processes=bool(args.processes),
                include_objects=bool(args.objects),
                include_ipc=bool(args.ipc),
                include_resources=bool(args.resources),
                strict=bool(args.strict),
            )
        else:
            cfg = AnalyzerConfig(strict=bool(args.strict))
        result = FragmentAnalyzer(cfg).analyze(data)
        if args.diagnostics:
            out = json.dumps({"snapshot_id": result["snapshot_id"],
                              "consistent": result["consistent"],
                              "diagnostics": result["diagnostics"]},
                             sort_keys=True, indent=2)
        elif args.json:
            from os5.fragment.report import to_json
            out = to_json(result)
        else:
            from os5.fragment.report import to_text
            out = to_text(result)
        if args.output:
            if _is_forbidden(args.output):
                print(f"error: refusing to write to host scope '{args.output}'", file=sys.stderr)
                return 2
            Path(args.output).write_text(out, encoding="utf-8")
        else:
            print(out, end="" if out.endswith("\n") else "\n")
        if args.strict and not result.get("consistent", True):
            return 1
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
