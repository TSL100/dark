#!/usr/bin/env python3
"""Central orchestration script for the DFIR modular parser pipeline.

Usage:
    python orchestrator.py --all <output_dir> <input_paths...>
    python orchestrator.py --select prefetch lnk --output <output_dir> <input_paths...>
    python orchestrator.py --list
    python orchestrator.py --merge <output.json> <input_dirs...>

Merges all per-artifact JSON files into a single Unified Timeline JSON
consumed directly by dfir_timeline_ui.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from parsers import PARSER_REGISTRY, BaseParser, SCHEMA_VERSION

# Extension → parser key mapping for automatic detection
EXTENSION_MAP: dict[str, str] = {
    ".pf": "prefetch",
    ".lnk": "lnk",
    ".automaticdestinations-ms": "jumplist",
    ".customdestinations-ms": "jumplist",
    ".hve": "amcache",
    ".reg": "shimcache",
}


def detect_parser(path: Path) -> str | None:
    """Auto-detect which parser should handle this path."""
    suffix = path.suffix.lower()
    if suffix in EXTENSION_MAP:
        return EXTENSION_MAP[suffix]

    name = path.name.lower()
    if "prefetch" in name or suffix == ".pf":
        return "prefetch"
    if "amcache" in name:
        return "amcache"
    if "userassist" in name or "user_assist" in name:
        return "userassist"
    if "bam" in name:
        return "bam"
    if "shellbag" in name or "shellbags" in name:
        return "shellbag"
    if "recycle" in name or "recycler" in name:
        return "recyclebin"
    if "recentdoc" in name:
        return "recentdocs"
    if "shimcache" in name or "appcompat" in name:
        return "shimcache"
    if suffix == ".lnk":
        return "lnk"
    if "jumplist" in name:
        return "jumplist"

    if path.is_dir():
        lower = str(path).lower()
        if "prefetch" in lower:
            return "prefetch"
        if "recent" in lower and "lnk" in lower:
            return "lnk"
        if "jumplist" in lower or "automaticdestinations" in lower:
            return "jumplist"
        if "amcache" in lower:
            return "amcache"
        if "shellbag" in lower:
            return "shellbag"
        if "recycle" in lower or "$recycle.bin" in lower:
            return "recyclebin"
        if "recentdoc" in lower:
            return "recentdocs"
        if "shimcache" in lower:
            return "shimcache"
        if "bam" in lower:
            return "bam"
        if "userassist" in lower:
            return "userassist"

    return None


def run_parser(parser_key: str, input_path: Path,
               output_dir: Path) -> list[dict[str, Any]]:
    """Run one parser on one input, write JSON, return parsed events."""
    parser_cls = PARSER_REGISTRY.get(parser_key)
    if parser_cls is None:
        print(f"  [SKIP] Unknown parser: {parser_key}", file=sys.stderr)
        return []

    parser: BaseParser = parser_cls()
    try:
        events = parser.parse(input_path)
    except Exception as exc:
        print(f"  [ERROR] {parser.display_name} on {input_path}: {exc}",
              file=sys.stderr)
        return []

    out_name = f"{parser_key}_{input_path.stem}.json"
    out_path = output_dir / out_name
    out_path.write_text(parser.to_json(events, str(input_path)),
                        encoding="utf-8")
    print(f"  [OK] {parser.display_name}: {len(events)} events -> {out_path.name}")
    return [ev.to_json_dict() for ev in events]


def merge_timelines(input_dirs: list[Path],
                    output_path: Path) -> int:
    """Merge all per-artifact JSON files into one Unified Timeline."""
    all_events: list[dict[str, Any]] = []
    sources: dict[str, int] = {}

    for idir in input_dirs:
        for jf in sorted(idir.glob("*.json")):
            try:
                doc = json.loads(jf.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                print(f"  [SKIP] {jf.name}: {exc}", file=sys.stderr)
                continue

            events = doc.get("events", [])
            for ev in events:
                if isinstance(ev, dict):
                    all_events.append(ev)
                    src = ev.get("source", "Unknown")
                    sources[src] = sources.get(src, 0) + 1

    def _sort_key(ev: dict[str, Any]):
        ts = ev.get("timestamp", "")
        if not ts:
            return (1, "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return (0, dt.isoformat())
        except ValueError:
            return (1, ts)

    all_events.sort(key=_sort_key)

    unified = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_events": len(all_events),
        "sources": sources,
        "events": all_events,
    }

    output_path.write_text(
        json.dumps(unified, indent=2, ensure_ascii=False), encoding="utf-8")
    return len(all_events)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="DFIR modular artifact parser orchestrator")
    ap.add_argument("--list", action="store_true",
                    help="List all available parsers")
    ap.add_argument("--all", action="store_true",
                    help="Run all parsers on all inputs")
    ap.add_argument("--select", nargs="+", metavar="TYPE",
                    help="Run specific parsers (e.g. prefetch lnk bam)")
    ap.add_argument("--auto", action="store_true",
                    help="Auto-detect parsers from input file extensions")
    ap.add_argument("--output", "-o", default="parsed_output",
                    help="Output directory (default: parsed_output)")
    ap.add_argument("--merge", nargs="+", metavar="DIR",
                    help="Merge directories of JSON files into unified timeline")
    ap.add_argument("--merge-output", default="unified_timeline.json",
                    help="Output path for merged timeline")
    ap.add_argument("inputs", nargs="*",
                    help="Input artifact files or directories")

    args = ap.parse_args()

    if args.list:
        print("Available parsers:")
        for key, cls in sorted(PARSER_REGISTRY.items()):
            print(f"  {key:15s}  {cls.display_name}")
        return 0

    if args.merge:
        merge_dirs = [Path(d) for d in args.merge]
        out = Path(args.merge_output)
        count = merge_timelines(merge_dirs, out)
        print(f"Merged {count} events -> {out}")
        return 0

    if not args.inputs:
        ap.print_help()
        return 1

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.select:
        parser_keys = args.select
    elif args.all:
        parser_keys = list(PARSER_REGISTRY.keys())
    elif args.auto:
        parser_keys = []
    else:
        parser_keys = list(PARSER_REGISTRY.keys())

    total = 0
    for input_str in args.inputs:
        input_path = Path(input_str)
        if not input_path.exists():
            print(f"  [SKIP] Not found: {input_path}", file=sys.stderr)
            continue

        if args.auto:
            detected = detect_parser(input_path)
            if detected:
                keys = [detected]
            else:
                print(f"  [SKIP] Cannot auto-detect: {input_path}",
                      file=sys.stderr)
                continue
        else:
            keys = parser_keys

        print(f"\nProcessing: {input_path}")
        for key in keys:
            events = run_parser(key, input_path, output_dir)
            total += len(events)

    print(f"\nTotal: {total} events written to {output_dir}/")

    unified_out = output_dir / "unified_timeline.json"
    count = merge_timelines([output_dir], unified_out)
    print(f"Unified timeline: {count} events -> {unified_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
