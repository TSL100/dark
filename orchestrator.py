#!/usr/bin/env python3
"""Central orchestration CLI for the DFIR Tier 1 pipeline.

All ingestion routes exclusively through the tested engines:

* :mod:`tier1_artifacts` — AcquisitionEngine (evidence-root auto-discovery,
  12 Tier 1 collectors, SHA-256 dedup, strict schema), and
* the direct robust parsers it reuses — ``lnk_forensics``,
  ``prefetch_parser``, ``jumplists_parser`` — plus tier1's native
  single-file parsers (``parse_recycle_i``, ``parse_zone_ads``,
  ``decode_ps_history``).

The legacy ``parsers/`` wrapper package was removed: it read timestamps
from wrong offsets, ignored its own input path in favour of the live
registry, and fed raw pipe-delimited text exports into mismatched
parsers. Nothing here accepts free-form text as evidence anymore.

Usage:
    python orchestrator.py --list
    python orchestrator.py --all -o parsed_output <evidence_root...>
    python orchestrator.py --select prefetch lnk -o out <evidence_root...>
    python orchestrator.py --auto <artifact_file...> [-o parsed_output]
    python orchestrator.py --merge <json_dir...> --merge-output unified.json

Every emitted record enforces the unified JSON v1.0 schema consumed
directly by dfir_timeline_ui.py.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import tier1_artifacts as tier1
    from tier1_artifacts import (
        TIER1,
        TIER1_IDS,
        AcquisitionEngine,
        Tier1Error,
        available as tier1_available,
        make_record,
        parse_jumplist_at,
        parse_lnk_at,
        parse_prefetch_at,
        parse_recycle_i,
        parse_zone_ads,
        decode_ps_history,
        record_identity,
    )
except ImportError as exc:  # pragma: no cover - engine ships alongside
    print(f"Fatal: tier1_artifacts.py unavailable ({exc})", file=sys.stderr)
    raise SystemExit(2)

SCHEMA_VERSION = "1.0"

#: Required keys of every emitted record (strict schema, v1.0).
STRICT_KEYS = (
    "timestamp_utc",
    "timestamp_raw",
    "source_file",
    "source_hash",
    "record_ref",
    "parser",
    "parser_version",
    "event_type",
    "target_path",
    "details",
    "raw_binary_hex",
)

#: Single-file extension/name routing for --auto (tier1 artifact ids only).
EXTENSION_MAP: dict[str, str] = {
    ".pf": "prefetch",
    ".lnk": "lnk",
    ".automaticdestinations-ms": "jumplist",
    ".customdestinations-ms": "jumplist",
}

#: Registry-backed artifacts cannot be parsed from a lone file; they need
#: an evidence-root directory so the engine can resolve hive locations.
NEEDS_ROOT_HINTS = (
    ".hve",
    ".dat",
    "amcache",
    "ntuser",
    "system",
    "software",
    "sam",
    "security",
)


def detect_artifact(path: Path) -> str | None:
    """Map one input file to a tier1 artifact id, or None if unroutable."""
    name = path.name
    lower = name.lower()
    suffix = path.suffix.lower()
    if suffix in EXTENSION_MAP:
        return EXTENSION_MAP[suffix]
    if name.upper().startswith("$I"):
        return "recyclebin"
    if lower == "zone.identifier" or ":zone.identifier" in lower:
        return "zoneid"
    if lower == "consolehost_history.txt":
        return "powershell"
    return None


def needs_root_hint(path: Path) -> str | None:
    """Explain why a lone file cannot feed a registry-backed artifact."""
    lower = path.name.lower() + " " + path.suffix.lower()
    if any(h in lower for h in NEEDS_ROOT_HINTS):
        return ("registry-backed artifacts (amcache/userassist/bam/usb/mru) "
                "need an evidence-root directory, not a lone file")
    return None


def valid_record(rec: Any) -> bool:
    """Strict v1.0 schema check: all keys present, hash well-formed."""
    if not isinstance(rec, dict):
        return False
    if any(k not in rec for k in STRICT_KEYS):
        return False
    if not isinstance(rec.get("details"), dict):
        return False
    digest = rec.get("source_hash", "")
    return (isinstance(digest, str) and len(digest) == 64
            and all(c in "0123456789abcdef" for c in digest))


def _repair_hash(rec: dict[str, Any]) -> bool:
    """Recompute a missing/malformed source_hash from the record itself."""
    digest = rec.get("source_hash", "")
    if (isinstance(digest, str) and len(digest) == 64
            and all(c in "0123456789abcdef" for c in digest)):
        return False
    rec["source_hash"] = record_identity(
        rec.get("source"), rec.get("source_file"),
        rec.get("timestamp_utc"), rec.get("event_type"),
        rec.get("target_path"))
    if isinstance(rec.get("details"), dict):
        rec["details"]["source_hash"] = rec["source_hash"]
    return True


def parse_single_file(path: Path, machine_id: str | None) -> tuple[list[dict], str]:
    """Parse one artifact file via tier1/direct parsers. Returns (records, note)."""
    artifact = detect_artifact(path)
    if artifact is None:
        hint = needs_root_hint(path)
        note = hint or "unrecognized file type (no tier1 route)"
        return [], note
    try:
        if artifact == "prefetch":
            return parse_prefetch_at(str(path), machine_id=machine_id), ""
        if artifact == "lnk":
            return parse_lnk_at(str(path), machine_id=machine_id), ""
        if artifact == "jumplist":
            return parse_jumplist_at(str(path), machine_id=machine_id), ""
        if artifact == "recyclebin":
            return _parse_single_recyclebin(path), ""
        if artifact == "zoneid":
            return _parse_single_zoneid(path), ""
        if artifact == "powershell":
            return _parse_single_history(path), ""
    except Tier1Error as exc:
        return [], str(exc)
    except (OSError, ValueError, struct.error) as exc:
        return [], f"{type(exc).__name__}: {exc}"
    return [], f"no tier1 route for {path.name}"


def _parse_single_recyclebin(path: Path) -> list[dict]:
    """Mirror tier1 collect_recyclebin construction for one $I file."""
    fields, raw = parse_recycle_i(str(path))
    sid = os.path.basename(os.path.dirname(os.path.abspath(path)))
    return [make_record(
        timestamp_utc=fields["deletion_time_utc"],
        timestamp_raw=fields["deletion_time_raw"],
        source_file=str(path),
        record_ref=path.name,
        parser="tier1_recyclebin",
        parser_version=tier1.VERSION,
        source="RecycleBin",
        artifact_type="recycle_bin_file",
        artifact_name=path.name,
        event_type="File Deleted",
        target_path=fields["original_path"],
        details={"original_name": fields["original_name"],
                 "original_path": fields["original_path"],
                 "file_size": fields["file_size"],
                 "sid": sid,
                 "timestamp_source": "deletion_filetime"},
        raw_bytes=raw)]


def _parse_single_zoneid(path: Path) -> list[dict]:
    """Mirror tier1 collect_zoneid construction for one ADS path."""
    text = str(path)
    host = text[:-len(":Zone.Identifier")] if ":Zone.Identifier" in text else text
    fields, raw = parse_zone_ads(text if ":Zone.Identifier" in text else text)
    try:
        host_mtime = dt.datetime.fromtimestamp(
            os.path.getmtime(host), dt.timezone.utc).isoformat()
    except OSError:
        host_mtime = None
    name = os.path.basename(host)
    return [make_record(
        timestamp_utc=host_mtime,
        timestamp_raw=host_mtime,
        source_file=text,
        record_ref="Zone.Identifier",
        parser="tier1_zoneid",
        parser_version=tier1.VERSION,
        source="ZoneIdentifier",
        artifact_type="zone_identifier_ads",
        artifact_name=f"{name}:Zone.Identifier",
        event_type="Zone Marking",
        target_path=host,
        details={"zone_id": fields["zone_id"],
                 "referrer_url": fields["referrer_url"],
                 "host_url": fields["host_url"],
                 "timestamp_source": "file_mtime"},
        raw_bytes=raw)]


def _parse_single_history(path: Path) -> list[dict]:
    """Mirror tier1 collect_powershell construction for one history file."""
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        moment = dt.datetime.fromtimestamp(
            os.path.getmtime(path), dt.timezone.utc).isoformat()
    except OSError:
        moment = None
    out = []
    for lineno, line in enumerate(decode_ps_history(data).splitlines(), 1):
        command = line.strip()
        if not command:
            continue
        out.append(make_record(
            timestamp_utc=moment,
            timestamp_raw=moment,
            source_file=str(path),
            record_ref=f"line:{lineno}",
            parser="tier1_powershell",
            parser_version=tier1.VERSION,
            source="PowerShell",
            artifact_type="powershell_history",
            artifact_name="ConsoleHost_history.txt",
            event_type="PowerShell Command",
            target_path=command[:300],
            details={"command": command,
                     "line_number": lineno,
                     "timestamp_source": "file_mtime"},
            raw_bytes=line.encode("utf-8", "replace")))
    return out


def _sort_key(rec: dict[str, Any]):
    ts = rec.get("timestamp_utc") or rec.get("timestamp") or ""
    if not ts:
        return (1, "")
    try:
        moment = dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return (1, str(ts))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return (0, moment.isoformat())


def write_doc(records: list[dict], path: Path, *, tool: str,
              extra_meta: dict[str, Any] | None = None) -> None:
    """Write one schema-validated, sorted, deduped JSON document."""
    seen: set[str] = set()
    clean, dropped = [], 0
    for rec in records:
        if not valid_record(rec):
            dropped += 1
            continue
        digest = rec["source_hash"]
        if digest in seen:
            dropped += 1
            continue
        seen.add(digest)
        clean.append(rec)
    clean.sort(key=_sort_key)
    sources: dict[str, int] = {}
    for rec in clean:
        src = rec.get("source", "Unknown")
        sources[src] = sources.get(src, 0) + 1
    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "generator": tool,
        "total_events": len(clean),
        "dropped_invalid": dropped,
        "sources": sources,
        "events": clean,
    }
    if extra_meta:
        doc["metadata"] = extra_meta
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False),
                    encoding="utf-8")


def run_evidence_root(root: Path, selected: list[str], machine_id: str | None,
                      output_dir: Path) -> tuple[int, dict]:
    """Acquire one evidence root via AcquisitionEngine; write per-run JSON."""
    engine = AcquisitionEngine(str(root), machine_id)
    records, report = engine.run(selected)
    for rec in records:
        if _repair_hash(rec):
            report.setdefault("_repaired_hashes", 0)
            report["_repaired_hashes"] += 1
    out_path = output_dir / f"tier1_{root.name}.json"
    write_doc(records, out_path, tool="orchestrator+tier1",
              extra_meta={"evidence_root": str(root),
                          "acquisition_report": report})
    print(f"  [OK] {root}: {len(records)} events -> {out_path.name}")
    for artifact, info in report.items():
        if artifact.startswith("_"):
            continue
        extra = f" ({info['note']})" if info.get("note") else ""
        print(f"       - {artifact}: {info.get('status')}: "
              f"{info.get('count', 0)} events{extra}")
    return len(records), report


def run_single_file(path: Path, machine_id: str | None,
                    output_dir: Path) -> int:
    """Parse one file via its tier1 route; write per-file JSON."""
    records, note = parse_single_file(path, machine_id)
    for rec in records:
        _repair_hash(rec)
    out_path = output_dir / f"single_{path.stem}.json"
    write_doc(records, out_path, tool="orchestrator+tier1",
              extra_meta={"input": str(path), "note": note})
    status = "OK" if records else "SKIP"
    print(f"  [{status}] {path.name}: {len(records)} events -> {out_path.name}"
          + (f" ({note})" if note and not records else ""))
    return len(records)


def merge_timelines(input_dirs: list[Path],
                    output_path: Path) -> int:
    """Merge JSON timeline dirs into one deduped unified timeline (v1.0)."""
    all_events: list[dict[str, Any]] = []
    dropped = 0
    for idir in input_dirs:
        if not idir.is_dir():
            print(f"  [SKIP] not a directory: {idir}", file=sys.stderr)
            continue
        for jf in sorted(idir.glob("*.json")):
            try:
                doc = json.loads(jf.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                print(f"  [SKIP] {jf.name}: {exc}", file=sys.stderr)
                dropped += 1
                continue
            events = doc.get("events", [])
            if not isinstance(events, list):
                print(f"  [SKIP] {jf.name}: no events list", file=sys.stderr)
                dropped += 1
                continue
            for ev in events:
                if not valid_record(ev):
                    dropped += 1
                    continue
                all_events.append(ev)
    seen: set[str] = set()
    clean = []
    dups = 0
    for ev in all_events:
        digest = ev["source_hash"]
        if digest in seen:
            dups += 1
            continue
        seen.add(digest)
        clean.append(ev)
    clean.sort(key=_sort_key)
    sources: dict[str, int] = {}
    for ev in clean:
        src = ev.get("source", "Unknown")
        sources[src] = sources.get(src, 0) + 1
    unified = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "total_events": len(clean),
        "dropped_invalid": dropped,
        "duplicates_skipped": dups,
        "sources": sources,
        "events": clean,
    }
    output_path.write_text(json.dumps(unified, indent=2, ensure_ascii=False),
                           encoding="utf-8")
    return len(clean)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="orchestrator.py",
        description="DFIR Tier 1 orchestrator: acquire evidence roots and "
                    "single artifact files through tier1_artifacts and the "
                    "direct robust parsers into one deduped unified timeline "
                    "(schema v1.0).")
    ap.add_argument("--list", action="store_true",
                    help="List Tier 1 artifacts (ids, labels, requirements)")
    ap.add_argument("--all", action="store_true",
                    help="Acquire all Tier 1 artifacts from each evidence root")
    ap.add_argument("--select", nargs="+", metavar="TYPE",
                    help="Acquire specific artifacts (e.g. prefetch lnk bam)")
    ap.add_argument("--auto", action="store_true",
                    help="Route each input file to its tier1 artifact parser")
    ap.add_argument("--machine-id", default=None,
                    help="Host identifier stamped when artifacts carry none")
    ap.add_argument("--output", "-o", default="parsed_output",
                    help="Output directory (default: parsed_output)")
    ap.add_argument("--merge", nargs="+", metavar="DIR",
                    help="Merge directories of JSON files into unified timeline")
    ap.add_argument("--merge-output", default="unified_timeline.json",
                    help="Output path for merged timeline")
    ap.add_argument("inputs", nargs="*",
                    help="Evidence roots (dirs) and/or single artifact files")
    args = ap.parse_args(argv)

    if args.list:
        print(f"Tier 1 artifacts (unified schema v{SCHEMA_VERSION}):")
        avail = tier1.available()
        for item in TIER1:
            ok, reason = avail.get(item["id"], (False, "unknown artifact"))
            flag = "ok " if ok else "N/A "
            extra = f"[{reason}]" if reason else ""
            print(f"  {flag} {item['id']:15s} {item['label']:34s} {extra}")
        return 0

    if args.merge:
        out = Path(args.merge_output)
        count = merge_timelines([Path(d) for d in args.merge], out)
        print(f"Merged {count} events -> {out}")
        return 0

    if not args.inputs:
        ap.print_help()
        return 1

    if args.select:
        selected = [s.strip().lower() for s in args.select]
        unknown = [s for s in selected if s not in tier1.TIER1_IDS]
        if unknown:
            print(f"Unknown artifact(s): {', '.join(unknown)}\n"
                  f"Valid ids: {', '.join(tier1.TIER1_IDS)}", file=sys.stderr)
            return 2
    elif args.all or not args.auto:
        selected = list(tier1.TIER1_IDS)
    else:
        selected = []

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    total = 0
    for input_str in args.inputs:
        input_path = Path(input_str)
        if not input_path.exists():
            print(f"  [SKIP] Not found: {input_path}", file=sys.stderr)
            continue
        if input_path.is_dir():
            if args.auto:
                print(f"  [SKIP] --auto needs files, not directories: "
                      f"{input_path} (drop --auto to acquire it as evidence root)",
                      file=sys.stderr)
                continue
            print(f"\nAcquiring evidence root: {input_path}")
            count, _report = run_evidence_root(
                input_path, selected, args.machine_id, output_dir)
            total += count
        else:
            if not args.auto and not args.select and not args.all:
                print(f"  [SKIP] Single file needs --auto (or pass its "
                      f"containing directory): {input_path}", file=sys.stderr)
                continue
            if args.auto:
                print(f"\nRouting file: {input_path}")
                total += run_single_file(input_path, args.machine_id, output_dir)
            else:
                print(f"  [SKIP] --select/--all apply to evidence roots, not "
                      f"single files: {input_path} (use --auto)", file=sys.stderr)
                continue

    print(f"\nTotal: {total} events written to {output_dir}/")

    unified_out = output_dir / "unified_timeline.json"
    count = merge_timelines([output_dir], unified_out)
    print(f"Unified timeline: {count} events -> {unified_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
