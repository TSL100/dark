#!/usr/bin/env python3
"""
tier1_artifacts.py - Tier 1 forensic acquisition engine for the DFIR suite.

Discovers, parses and normalizes analyst-selected Tier 1 artifacts from
their standard system paths (live host) or from an evidence root
(offline image / triage collection with the same layout), and emits
records that satisfy BOTH:

1. The strict acquisition schema (hash-deduped, fully sourced):
     timestamp_utc / timestamp_raw / source_file / source_hash (SHA-256) /
     record_ref / parser / parser_version / event_type / target_path /
     details / raw_binary_hex
2. The unified timeline schema already consumed by dfir_timeline_ui.py
   (timestamp / timestamp_type / source / artifact_type / artifact_name /
   target_path / details), so results feed the Master Timeline, Timeline
   Table and Relationship Graph with zero GUI format changes.

Covered artifacts (ids in TIER1, in checklist order):
  prefetch    C:\\Windows\\Prefetch\\*.pf (reuses prefetch_parser)
  amcache     C:\\Windows\\appcompat\\Programs\\Amcache.hve (needs regipy)
  userassist  NTUSER.DAT UserAssist keys (needs regipy)
  bam         SYSTEM hive BAM keys (needs regipy)
  lnk         %AppData%\\...\\Recent\\*.lnk (reuses lnk_forensics)
  jumplist    Recent\\AutomaticDestinations (+Custom) (reuses jumplists_parser)
  recyclebin  $Recycle.Bin\\$I* files (pure struct parsing)
  zoneid      Zone.Identifier ADS on Recent/Desktop/Downloads files
  usb         SYSTEM USBSTOR + MountedDevices (needs regipy)
  mru         NTUSER.DAT RecentDocs/RunMRU/TypedPaths/OpenSaveMRU (needs regipy)
  powershell  ConsoleHost_history.txt per user

Deduplication: every record carries source_hash = SHA-256 over the canonical
identity (source, file basename, timestamp, event type, target). The engine
drops repeats inside one run; the GUI additionally filters against a session
set (seeded from loaded timelines) so re-running acquisition never duplicates.

Honesty rules applied throughout:
* Locked / missing hives (live SYSTEM/NTUSER.DAT) -> per-artifact note with
  the exact path and a remediation hint, never a crash. (DFIR norm is an
  offline image or triage copy; `reg save` can produce readable copies.)
* Amcache value semantics are labeled (link_date is PE-local time; sha1 and
  path matches are labeled candidates; key LastWrite is the fallback clock).
* Timestamps always carry timestamp_source (destlist_last_access,
  lnk_target_modification, key_lastwrite, file_mtime, ...).
* raw_binary_hex holds full bytes under 4 KiB, else the first 512 bytes with
  details.raw_truncated=true.
* There is no Machine SID in any of these artifacts; host correlation uses
  NetBIOS names, volume serials, DROID GUIDs and USB serials.

Dependencies: Python 3.8+ stdlib only, plus OPTIONAL regipy (pip install
regipy) for the five registry-backed artifacts. The three file parsers are
reused from this directory; nothing else is required.
"""

from __future__ import annotations

import argparse
import codecs
import datetime as dt
import glob
import hashlib
import json
import ntpath
import os
import re
import struct
import sys

TOOL = "tier1_artifacts.py"
VERSION = "1.0.0"

try:
    from regipy.registry import RegistryHive
    from regipy.exceptions import RegistryKeyNotFoundException
except ImportError:  # optional dependency; registry artifacts degrade gracefully
    RegistryHive = None
    RegistryKeyNotFoundException = Exception

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import lnk_forensics
    from lnk_forensics import make_events as lnk_make_events
    from lnk_forensics import parse_lnk_builtin, iter_lnk_files
    LNK_VERSION = getattr(lnk_forensics, "VERSION", "1.0.0")
except ImportError:  # pragma: no cover - sibling module expected alongside
    lnk_make_events = parse_lnk_builtin = iter_lnk_files = None
    LNK_VERSION = "1.0.0"
try:
    import prefetch_parser
    from prefetch_parser import make_events as pf_make_events
    from prefetch_parser import parse_prefetch_file, iter_pf_files
    PF_VERSION = getattr(prefetch_parser, "VERSION", "1.0.0")
except ImportError:  # pragma: no cover
    pf_make_events = parse_prefetch_file = iter_pf_files = None
    PF_VERSION = "1.0.0"
try:
    import jumplists_parser
    from jumplists_parser import make_events as jl_make_events
    from jumplists_parser import parse_jumplist_file, iter_jumplist_files
    JL_VERSION = getattr(jumplists_parser, "VERSION", "1.0.0")
except ImportError:  # pragma: no cover
    jl_make_events = parse_jumplist_file = iter_jumplist_files = None
    JL_VERSION = "1.0.0"

FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
MAX_RAW_HEX_FULL = 4096
MAX_RAW_HEX_HEAD = 512
MAX_ZONE_SCAN_FILES = 5000
MAX_RECYCLE_WALK = 2000
SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
PATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\\?\\|\\\\[A-Za-z0-9_.$-]+\\[^\\])")

TIER1 = [
    {"id": "prefetch", "label": "Prefetch", "needs_regipy": False},
    {"id": "amcache", "label": "Amcache", "needs_regipy": True},
    {"id": "userassist", "label": "UserAssist", "needs_regipy": True},
    {"id": "bam", "label": "BAM", "needs_regipy": True},
    {"id": "lnk", "label": "LNK Files", "needs_regipy": False},
    {"id": "jumplist", "label": "Jump Lists", "needs_regipy": False},
    {"id": "recyclebin", "label": "Recycle Bin ($I)", "needs_regipy": False},
    {"id": "zoneid", "label": "Zone.Identifier", "needs_regipy": False},
    {"id": "usb", "label": "USB History", "needs_regipy": True},
    {"id": "mru", "label": "RecentDocs / RunMRU / TypedPaths", "needs_regipy": True},
    {"id": "powershell", "label": "PowerShell History", "needs_regipy": False},
]
TIER1_IDS = [a["id"] for a in TIER1]


class Tier1Error(Exception):
    """Raised for artifact-level failures (missing/locked/unreadable)."""


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def filetime_to_iso(value):
    if not value:
        return None
    try:
        moment = FILETIME_EPOCH + dt.timedelta(microseconds=value // 10)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.astimezone(dt.timezone.utc).isoformat()


def _base(path):
    return ntpath.basename((path or "").rstrip("\\/")) or (path or "")


def record_identity(source, source_file, timestamp_utc, event_type, target_path):
    """Canonical dedup identity (basename on purpose: stable across roots)."""
    canon = "\n".join([
        source or "",
        _base(source_file),
        timestamp_utc or "",
        event_type or "",
        target_path or "",
    ])
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def identity_of_timeline_record(rec):
    """Best-effort identity for an already-loaded GUI TimelineRecord."""
    raw = getattr(rec, "raw", {}) or {}
    if not isinstance(raw, dict):
        raw = {}
    source_file = (
        raw.get("source_file") or raw.get("lnk_path") or raw.get("prefetch_path")
        or raw.get("jumplists_path") or getattr(rec, "artifact_name", ""))
    return record_identity(
        getattr(rec, "artifact_source", ""), source_file,
        getattr(rec, "timestamp", ""), getattr(rec, "event_type", ""),
        getattr(rec, "target_path", ""))


def make_record(*, timestamp_utc=None, timestamp_raw=None, source_file="",
                record_ref="", parser="", parser_version="1.0.0",
                source="", artifact_type="", artifact_name="",
                event_type="", target_path="", machine_id=None,
                details=None, raw_bytes=b""):
    """Build one unified record: strict acquisition schema + timeline keys."""
    details = dict(details or {})
    details["parser"] = parser
    details["parser_version"] = parser_version
    if machine_id is not None:
        details.setdefault("machine_id", machine_id)
    else:
        details.setdefault("machine_id", None)
    source_hash = record_identity(source, source_file, timestamp_utc,
                                  event_type, target_path)
    details["source_hash"] = source_hash
    if raw_bytes is None:
        raw_bytes = b""
    if len(raw_bytes) > MAX_RAW_HEX_FULL:
        details["raw_truncated"] = True
        raw_hex = bytes(raw_bytes[:MAX_RAW_HEX_HEAD]).hex()
    else:
        raw_hex = bytes(raw_bytes).hex()
    name = artifact_name or _base(source_file) or source_file
    return {
        # strict acquisition schema
        "timestamp_utc": timestamp_utc,
        "timestamp_raw": timestamp_raw,
        "source_file": os.path.abspath(source_file) if source_file else "",
        "source_hash": source_hash,
        "record_ref": record_ref,
        "parser": parser,
        "parser_version": parser_version,
        "event_type": event_type,
        "target_path": target_path,
        "details": details,
        "raw_binary_hex": raw_hex,
        # unified timeline bridge (consumed as-is by dfir_timeline_ui)
        "timestamp": timestamp_utc,
        "timestamp_type": event_type,
        "source": source,
        "artifact_type": artifact_type,
        "artifact_name": name,
    }


# --------------------------------------------------------------------------
# registry access (regipy optional)
# --------------------------------------------------------------------------

def _require_regipy():
    if RegistryHive is None:
        raise Tier1Error("needs: pip install regipy")


def _open_hive(path):
    _require_regipy()
    if not os.path.isfile(path):
        raise Tier1Error(f"hive not present: {path}")
    try:
        return RegistryHive(path)
    except Tier1Error:
        raise
    except Exception as exc:  # locked / corrupt / unreadable
        raise Tier1Error(f"cannot open hive {path} ({exc}). "
                         f"Live hives are locked; analyze an offline image or "
                         f"a triage copy (e.g. via `reg save`).")


def _get_key(hive, path):
    try:
        key = hive.get_key(path)
    except Exception:
        return None
    return key


def _key_time_iso(key):
    try:
        value = key.header.last_modified
    except AttributeError:
        return None
    if isinstance(value, dt.datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
        return moment.astimezone(dt.timezone.utc).isoformat()
    if isinstance(value, int):
        return filetime_to_iso(value)
    return None


def _reg_bytes(value_obj):
    """Raw bytes of a regipy value, whatever shape it arrived in."""
    raw = getattr(value_obj, "value", None)
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        if text and len(text) % 2 == 0:
            try:
                return bytes.fromhex(text)
            except ValueError:
                return None
        return None
    return None


def _reg_str(value_obj):
    raw = getattr(value_obj, "value", None)
    if isinstance(raw, str):
        return raw
    if isinstance(raw, bytes):
        for codec in ("utf-16-le", "utf-8-sig", "cp1252"):
            try:
                text = raw.decode(codec)
            except (ValueError, OverflowError):
                continue
            text = text.split("\x00")[0].strip()
            if text:
                return text
        return None
    if isinstance(raw, int):
        return str(raw)
    if isinstance(raw, list):
        parts = [p for p in (_reg_str(type("V", (), {"value": p})()) for p in raw) if p]
        return "; ".join(parts) or None
    return None


def _u32(data, off):
    if off < 0 or off + 4 > len(data):
        raise Tier1Error("binary value truncated")
    return struct.unpack_from("<I", data, off)[0]


def _u64(data, off):
    if off < 0 or off + 8 > len(data):
        raise Tier1Error("binary value truncated")
    return struct.unpack_from("<Q", data, off)[0]


def _utf16_prefix(raw, limit=260):
    """Best-effort display string from a shell-ish binary blob."""
    try:
        text = bytes(raw).decode("utf-16-le", "replace").split("\x00")[0]
    except (ValueError, OverflowError):
        return None
    text = "".join(ch for ch in text if ch.isprintable() or ch in " \t")
    text = text.strip()
    if len(text) < 2:
        return None
    return text[:limit]


def _mru_order(mru_blob):
    """Parse MRUListEx bytes -> ordered id list (best effort)."""
    order = []
    if not mru_blob or len(mru_blob) < 4:
        return order
    for off in range(0, len(mru_blob) - 3, 4):
        value = struct.unpack_from("<I", mru_blob, off)[0]
        if value == 0xFFFFFFFF:
            break
        order.append(value)
    return order


# --------------------------------------------------------------------------
# path resolution (live host vs evidence root)
# --------------------------------------------------------------------------

class Paths:
    def __init__(self, evidence_root=None):
        self.root = os.path.abspath(evidence_root) if evidence_root else None
        win = os.path.join(self.root, "Windows") if self.root else (
            os.environ.get("SystemRoot", r"C:\Windows"))
        self.windows = win
        users_base = os.path.join(self.root, "Users") if self.root else r"C:\Users"
        self.users = sorted(
            d for d in glob.glob(os.path.join(users_base, "*"))
            if os.path.isdir(d) and os.path.basename(d).lower() not in
            {"default", "default user", "public", "all users"})
        if not self.root and not self.users:
            home = os.path.expanduser("~")
            if os.path.isdir(home):
                self.users = [home]

    def user_sub(self, *parts):
        for user in self.users:
            candidate = os.path.join(user, *parts)
            if os.path.exists(candidate):
                yield user, candidate

    def drives(self):
        if self.root:
            yield self.root
            return
        import string
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.isdir(drive):
                yield drive


# --------------------------------------------------------------------------
# adapters: reuse the three proven file parsers
# --------------------------------------------------------------------------

def _adapt_events(events, *, parser, parser_version, source_file,
                  ref_of, raw_hex=""):
    out = []
    for ev in events:
        details = dict(ev.get("details") or {})
        ref = ref_of(ev, details)
        rec = make_record(
            timestamp_utc=ev.get("timestamp"),
            timestamp_raw=ev.get("timestamp"),
            source_file=source_file,
            record_ref=ref,
            parser=parser,
            parser_version=parser_version,
            source=ev.get("source", ""),
            artifact_type=ev.get("artifact_type", ""),
            artifact_name=ev.get("artifact_name") or _base(source_file),
            event_type=ev.get("timestamp_type") or ev.get("event_type", ""),
            target_path=ev.get("target_path"),
            machine_id=details.get("machine_id"),
            details=details,
            raw_bytes=b"")
        rec["raw_binary_hex"] = raw_hex
        out.append(rec)
    return out


def parse_prefetch_at(path, machine_id=None):
    """Adapt prefetch_parser output to unified strict records."""
    if parse_prefetch_file is None:
        raise Tier1Error("prefetch_parser module unavailable")
    record = parse_prefetch_file(path, machine_id=machine_id)
    base = record["prefetch_file"]
    events = pf_make_events(record)

    def ref_of(ev, details):
        index = details.get("run_index")
        if index is None:
            return f"{base}#file"
        return f"{base}#slot{index}"

    return _adapt_events(events, parser="prefetch_parser",
                         parser_version=PF_VERSION, source_file=record["prefetch_path"],
                         ref_of=ref_of)


def parse_lnk_at(path, machine_id=None):
    """Adapt lnk_forensics output to unified strict records."""
    if parse_lnk_builtin is None:
        raise Tier1Error("lnk_forensics module unavailable")
    record = parse_lnk_builtin(path)
    # parse_*() leaves parsers_used to the CLI; adapters stamp the engine used.
    record.setdefault("parsers_used", ["builtin"])
    if machine_id is not None and not record.get("machine_id"):
        record["machine_id"] = machine_id
    base = record["lnk_file"] or _base(path)
    events = lnk_make_events(record)

    def ref_of(ev, _details):
        return base

    return _adapt_events(events, parser="lnk_forensics",
                         parser_version=LNK_VERSION,
                         source_file=record["lnk_path"] or path,
                         ref_of=ref_of)


def parse_jumplist_at(path, machine_id=None, appid_table=None):
    """Adapt jumplists_parser output to unified strict records."""
    if parse_jumplist_file is None:
        raise Tier1Error("jumplists_parser module unavailable")
    record = parse_jumplist_file(path, machine_id=machine_id, appid_table=appid_table)
    base = record["jumplists_file"]
    events = jl_make_events(record)

    def ref_of(ev, details):
        entry = details.get("entry_id")
        if entry is not None:
            return f"{base}#entry{entry}"
        carve = details.get("carve_index")
        if carve is not None:
            return f"{base}#carve{carve}"
        return f"{base}#file"

    return _adapt_events(events, parser="jumplists_parser",
                         parser_version=JL_VERSION,
                         source_file=record["jumplists_path"], ref_of=ref_of)


# --------------------------------------------------------------------------
# native parsers: $I recycle bin
# --------------------------------------------------------------------------

def parse_recycle_i(path):
    """Parse a $I file. Returns (fields_dict, raw_bytes)."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 28:
        raise Tier1Error(f"$I file too small ({len(data)} bytes)")
    file_size = struct.unpack_from("<Q", data, 8)[0]
    deletion_iso = filetime_to_iso(struct.unpack_from("<Q", data, 16)[0])
    name_len = struct.unpack_from("<I", data, 24)[0]
    name_bytes = data[28:28 + name_len * 2]
    if len(name_bytes) < name_len * 2:
        name = data[28:].decode("utf-16-le", "replace").split("\x00")[0]
    else:
        name = name_bytes.decode("utf-16-le", "replace").split("\x00")[0]
    return {
        "original_path": name or None,
        "original_name": _base(name) if name else None,
        "file_size": file_size,
        "deletion_time_utc": deletion_iso,
        "deletion_time_raw": struct.unpack_from("<Q", data, 16)[0],
        "header": data[:8].hex(),
    }, data


def collect_recyclebin(paths):
    """Walk $Recycle.Bin trees on all candidate drives/roots."""
    records, notes, seen = [], [], 0
    for drive in paths.drives():
        rb = os.path.join(drive, "$Recycle.Bin")
        if not os.path.isdir(rb):
            continue
        for dirpath, _dirnames, filenames in os.walk(rb):
            for name in sorted(filenames):
                if not name.startswith("$I"):
                    continue
                if seen >= MAX_RECYCLE_WALK:
                    notes.append(f"$I scan capped at {MAX_RECYCLE_WALK} files")
                    break
                seen += 1
                full = os.path.join(dirpath, name)
                try:
                    fields, raw = parse_recycle_i(full)
                except (OSError, Tier1Error, struct.error) as exc:
                    notes.append(f"{full}: skipped ({exc})")
                    continue
                sid = os.path.basename(os.path.dirname(full))
                records.append(make_record(
                    timestamp_utc=fields["deletion_time_utc"],
                    timestamp_raw=fields["deletion_time_raw"],
                    source_file=full,
                    record_ref=name,
                    parser="tier1_recyclebin",
                    parser_version=VERSION,
                    source="RecycleBin",
                    artifact_type="recycle_bin_file",
                    artifact_name=name,
                    event_type="File Deleted",
                    target_path=fields["original_path"],
                    details={"original_name": fields["original_name"],
                             "original_path": fields["original_path"],
                             "file_size": fields["file_size"],
                             "sid": sid,
                             "timestamp_source": "deletion_filetime"},
                    raw_bytes=raw))
            if seen >= MAX_RECYCLE_WALK:
                break
    if not records and not notes:
        notes.append("no $Recycle.Bin data found")
    return records, notes


# --------------------------------------------------------------------------
# native parsers: Zone.Identifier ADS
# --------------------------------------------------------------------------

def parse_zone_ads(ads_path):
    with open(ads_path, "rb") as fh:
        data = fh.read()
    for codec in ("utf-8-sig", "cp1252"):
        try:
            text = data.decode(codec)
            break
        except (ValueError, OverflowError):
            continue
    else:
        raise Tier1Error("Zone.Identifier is not text-decodable")
    fields = {}
    for line in text.splitlines():
        line = line.strip().strip("\x00")
        if not line or line.startswith(("[", ";")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip()] = value.strip()
    if "ZoneId" not in fields:
        raise Tier1Error("no ZoneId value in stream")
    try:
        zone_id = int(fields["ZoneId"])
    except ValueError:
        raise Tier1Error(f"bad ZoneId value {fields['ZoneId']!r}")
    return {"zone_id": zone_id,
            "referrer_url": fields.get("ReferrerUrl"),
            "host_url": fields.get("HostUrl")}, data


def collect_zoneid(paths):
    records, notes = [], []
    scanned = 0
    scope = ("AppData\\Roaming\\Microsoft\\Windows\\Recent",
             "Desktop", "Downloads")
    for user in paths.users:
        for part in scope:
            folder = os.path.join(user, *part.split("\\"))
            if not os.path.isdir(folder):
                continue
            try:
                names = sorted(os.listdir(folder))
            except OSError:
                continue
            for name in names:
                if scanned >= MAX_ZONE_SCAN_FILES:
                    notes.append(f"Zone.Identifier scan capped at {MAX_ZONE_SCAN_FILES} files")
                    break
                full = os.path.join(folder, name)
                if not os.path.isfile(full):
                    continue
                scanned += 1
                ads = full + ":Zone.Identifier"
                try:
                    with open(ads, "rb"):
                        pass
                except OSError:
                    continue
                try:
                    fields, raw = parse_zone_ads(ads)
                except (OSError, Tier1Error) as exc:
                    notes.append(f"{name}: ADS unreadable ({exc})")
                    continue
                try:
                    host_mtime = dt.datetime.fromtimestamp(
                        os.path.getmtime(full), dt.timezone.utc).isoformat()
                except OSError:
                    host_mtime = None
                records.append(make_record(
                    timestamp_utc=host_mtime,
                    timestamp_raw=host_mtime,
                    source_file=ads,
                    record_ref="Zone.Identifier",
                    parser="tier1_zoneid",
                    parser_version=VERSION,
                    source="ZoneIdentifier",
                    artifact_type="zone_identifier_ads",
                    artifact_name=f"{name}:Zone.Identifier",
                    event_type="Zone Marking",
                    target_path=full,
                    details={"zone_id": fields["zone_id"],
                             "referrer_url": fields["referrer_url"],
                             "host_url": fields["host_url"],
                             "timestamp_source": "file_mtime"},
                    raw_bytes=raw))
            if scanned >= MAX_ZONE_SCAN_FILES:
                break
    if not records and not notes:
        notes.append("no Zone.Identifier streams found (non-NTFS or none present)")
    return records, notes


# --------------------------------------------------------------------------
# native parsers: PowerShell history
# --------------------------------------------------------------------------

def decode_ps_history(data):
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", "replace")
    sample = data[:4096]
    nul_ratio = sample.count(b"\x00") / max(1, len(sample))
    if nul_ratio > 0.2:
        return data.decode("utf-16-le", "replace")
    return data.decode("utf-8", "replace")


def collect_powershell(paths):
    records, notes = [], []
    rel = os.path.join("AppData", "Roaming", "Microsoft", "Windows",
                       "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
    found = False
    for user, path in paths.user_sub(rel):
        found = True
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            notes.append(f"{path}: unreadable ({exc})")
            continue
        try:
            moment = dt.datetime.fromtimestamp(
                os.path.getmtime(path), dt.timezone.utc).isoformat()
        except OSError:
            moment = None
        for lineno, line in enumerate(decode_ps_history(data).splitlines(), 1):
            command = line.strip()
            if not command:
                continue
            records.append(make_record(
                timestamp_utc=moment,
                timestamp_raw=moment,
                source_file=path,
                record_ref=f"line:{lineno}",
                parser="tier1_powershell",
                parser_version=VERSION,
                source="PowerShell",
                artifact_type="powershell_history",
                artifact_name="ConsoleHost_history.txt",
                event_type="PowerShell Command",
                target_path=command[:300],
                details={"command": command,
                         "line_number": lineno,
                         "timestamp_source": "file_mtime"},
                raw_bytes=line.encode("utf-8", "replace")))
    if not found:
        notes.append("no ConsoleHost_history.txt found")
    return records, notes


# --------------------------------------------------------------------------
# registry-backed parsers (need regipy)
# --------------------------------------------------------------------------

def _iter_ntuser_keys(paths):
    """Yield (user, ntuser_path, RegistryHive) for readable NTUSER.DAT files."""
    _require_regipy()
    for user in paths.users:
        hive_path = os.path.join(user, "NTUSER.DAT")
        if not os.path.isfile(hive_path):
            continue
        try:
            yield user, hive_path, RegistryHive(hive_path)
        except Exception as exc:
            raise Tier1Error(f"cannot open {hive_path} ({exc}). Live hives are "
                             f"locked; use an offline image or triage copy.")


def collect_userassist(paths, machine_id=None):
    _require_regipy()
    base = ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    records, notes, skipped = [], [], 0
    try:
        hives = list(_iter_ntuser_keys(paths))
    except Tier1Error as exc:
        return [], [str(exc)]
    if not hives:
        return [], ["no readable NTUSER.DAT found"]
    for user, hive_path, hive in hives:
        root = _get_key(hive, "\\" + base)
        if root is None:
            notes.append(f"{user}: no UserAssist key")
            continue
        for guid_key in root.iter_subkeys():
            try:
                count = guid_key.get_subkey("Count")
            except Exception:
                continue
            if count is None:
                continue
            for value in count.iter_values():
                try:
                    name = codecs.decode(value.name, "rot13")
                except Exception:
                    continue
                raw = _reg_bytes(value)
                if raw is None or len(raw) < 8:
                    skipped += 1
                    continue
                try:
                    run_raw = _u32(raw, 4)
                    last_iso = filetime_to_iso(_u64(raw, 60)) if len(raw) >= 68 else None
                except Tier1Error:
                    skipped += 1
                    continue
                runs = run_raw - 5 if run_raw > 5 else run_raw
                stamp = last_iso or _key_time_iso(count)
                records.append(make_record(
                    timestamp_utc=stamp,
                    timestamp_raw=_u64(raw, 60) if len(raw) >= 68 else None,
                    source_file=hive_path,
                    record_ref=f"UserAssist\\{guid_key.name}\\Count\\{value.name}",
                    parser="tier1_userassist",
                    parser_version=VERSION,
                    source="UserAssist",
                    artifact_type="userassist_entry",
                    artifact_name=f"UserAssist Count ({os.path.basename(user)})",
                    event_type="Program Executed",
                    target_path=name,
                    machine_id=machine_id,
                    details={"executable_path": name,
                             "run_count": runs,
                             "run_count_raw": run_raw,
                             "userassist_guid": guid_key.name,
                             "user": os.path.basename(user),
                             "timestamp_source": ("last_run_filetime"
                                                  if last_iso else "key_lastwrite")},
                    raw_bytes=raw))
    if skipped:
        notes.append(f"{skipped} UserAssist values undecodable")
    if not records and not notes:
        notes.append("no UserAssist entries recovered")
    return records, notes


def _mru_value_display(value_obj):
    raw = _reg_bytes(value_obj)
    if raw is None:
        return _reg_str(value_obj), None
    return _utf16_prefix(raw), raw


def collect_mru(paths, machine_id=None):
    _require_regipy()
    base = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
    jobs = [
        ("RecentDocs", "Recent Document Opened"),
        ("RunMRU", "Run Command Executed"),
        ("TypedPaths", "Path Typed"),
    ]
    records, notes = [], []
    try:
        hives = list(_iter_ntuser_keys(paths))
    except Tier1Error as exc:
        return [], [str(exc)]
    if not hives:
        return [], ["no readable NTUSER.DAT found"]
    for user, hive_path, hive in hives:
        who = os.path.basename(user)
        for sub, event_type in jobs:
            key = _get_key(hive, "\\" + base + "\\" + sub)
            if key is None:
                continue
            stamp = _key_time_iso(key)
            values = {v.name: v for v in key.iter_values()}
            order_blob = _reg_bytes(values.get("MRUListEx")) if "MRUListEx" in values else None
            order = _mru_order(order_blob) if order_blob else []
            mru_list = values.get("MRUList")
            if not order and isinstance(mru_list.value if mru_list else None, str):
                order = [c for c in mru_list.value]
            pos_of = {}
            for position, ident in enumerate(order):
                pos_of[str(ident)] = position
                try:
                    pos_of[int(ident)] = position
                except (TypeError, ValueError):
                    pass
            for name, value in values.items():
                if name in ("MRUList", "MRUListEx"):
                    continue
                if sub == "RunMRU":
                    display = (_reg_str(value) or "").rstrip("\\1")
                    display = display[:-2] if display.endswith("\\1") else display
                else:
                    display, _raw = _mru_value_display(value)
                if not display:
                    display = name
                records.append(make_record(
                    timestamp_utc=stamp,
                    timestamp_raw=stamp,
                    source_file=hive_path,
                    record_ref=f"{sub}\\{name}",
                    parser="tier1_mru",
                    parser_version=VERSION,
                    source="RegistryMRU",
                    artifact_type="mru_entry",
                    artifact_name=f"{sub} ({who})",
                    event_type=event_type,
                    target_path=display,
                    machine_id=machine_id,
                    details={"mru_list": sub,
                             "mru_position": pos_of.get(name),
                             "value_name": name,
                             "user": who,
                             "timestamp_source": "key_lastwrite"},
                    raw_bytes=_reg_bytes(value) or b""))
        for parent, subtype in (
                ("ComDlg32\\OpenSavePidlMRU", "File Saved/Open Dialog"),
                ("ComDlg32\\LastVisitedPidlMRU", "Last Visited Dialog")):
            parent_key = _get_key(hive, "\\" + base + "\\" + parent)
            if parent_key is None:
                continue
            for ext_key in parent_key.iter_subkeys():
                stamp = _key_time_iso(ext_key)
                values = {v.name: v for v in ext_key.iter_values()}
                order_blob = _reg_bytes(values.get("MRUListEx")) if "MRUListEx" in values else None
                order = _mru_order(order_blob) if order_blob else []
                pos_of = {str(i): p for p, i in enumerate(order)}
                for name, value in values.items():
                    if name in ("MRUList", "MRUListEx"):
                        continue
                    display, raw = _mru_value_display(value)
                    records.append(make_record(
                        timestamp_utc=stamp,
                        timestamp_raw=stamp,
                        source_file=hive_path,
                        record_ref=f"{parent}\\{ext_key.name}\\{name}",
                        parser="tier1_mru",
                        parser_version=VERSION,
                        source="RegistryMRU",
                        artifact_type="mru_entry",
                        artifact_name=f"{parent.split(chr(92))[-1]} ({who})",
                        event_type=subtype,
                        target_path=display or f"{ext_key.name}\\{name}",
                        machine_id=machine_id,
                        details={"mru_list": f"{parent}\\{ext_key.name}",
                                 "mru_position": pos_of.get(str(name)),
                                 "value_name": name,
                                 "user": who,
                                 "timestamp_source": "key_lastwrite"},
                        raw_bytes=raw or b""))
    if not records and not notes:
        notes.append("no MRU entries recovered")
    return records, notes


def collect_bam(paths, machine_id=None):
    _require_regipy()
    sys_path = os.path.join(paths.windows, "System32", "config", "SYSTEM")
    try:
        hive = _open_hive(sys_path)
    except Tier1Error as exc:
        return [], [str(exc)]
    records, notes = [], []
    for rel in ("ControlSet001\\Services\\bam\\State\\UserSettings",
                "ControlSet001\\Services\\bam\\UserSettings"):
        root = _get_key(hive, "\\" + rel)
        if root is None:
            continue
        for sid_key in root.iter_subkeys():
            for value in sid_key.iter_values():
                name = value.name or ""
                if not name.startswith(("\\", "Microsoft.")) or name in (
                        "Version", "SequenceNumber"):
                    if name in ("Version", "SequenceNumber"):
                        continue
                    if not (name.startswith("\\") or "\\" in name or "." in name):
                        continue
                raw = _reg_bytes(value)
                if raw is None or len(raw) < 8:
                    continue
                try:
                    stamp_raw = _u64(raw, 0)
                except Tier1Error:
                    continue
                records.append(make_record(
                    timestamp_utc=filetime_to_iso(stamp_raw),
                    timestamp_raw=stamp_raw,
                    source_file=sys_path,
                    record_ref=f"{rel}\\{sid_key.name}\\{name}",
                    parser="tier1_bam",
                    parser_version=VERSION,
                    source="BAM",
                    artifact_type="bam_entry",
                    artifact_name=f"BAM ({sid_key.name})",
                    event_type="Program Executed",
                    target_path=name,
                    machine_id=machine_id,
                    details={"user_sid": sid_key.name,
                             "timestamp_source": "bam_filetime"},
                    raw_bytes=raw))
        if records:
            break
    if not records and not notes:
        notes.append("no BAM entries recovered")
    return records, notes


def collect_usb(paths, machine_id=None):
    _require_regipy()
    sys_path = os.path.join(paths.windows, "System32", "config", "SYSTEM")
    try:
        hive = _open_hive(sys_path)
    except Tier1Error as exc:
        return [], [str(exc)]
    records, notes = [], []
    enum = _get_key(hive, "\\ControlSet001\\Enum")
    if enum is not None:
        usb = None
        try:
            usb = enum.get_subkey("USBSTOR")
        except Exception:
            usb = None
        if usb is None:
            notes.append("no USBSTOR devices present")
        else:
            for dev_key in usb.iter_subkeys():
                parts = dev_key.name.split("&")
                vendor = product = rev = None
                for part in parts:
                    upper = part.upper()
                    if upper.startswith("VEN_"):
                        vendor = part[4:]
                    elif upper.startswith("PROD_"):
                        product = part[5:]
                    elif upper.startswith("REV_"):
                        rev = part[4:]
                for inst in dev_key.iter_subkeys():
                    serial = inst.name.split("&")[0]
                    stamp = _key_time_iso(inst)
                    friendly = None
                    try:
                        fv = inst.get_value("FriendlyName")
                        friendly = _reg_str(fv)
                    except Exception:
                        friendly = None
                    records.append(make_record(
                        timestamp_utc=stamp,
                        timestamp_raw=stamp,
                        source_file=sys_path,
                        record_ref=f"USBSTOR\\{dev_key.name}\\{inst.name}",
                        parser="tier1_usb",
                        parser_version=VERSION,
                        source="USB",
                        artifact_type="usbstor_device",
                        artifact_name=f"USBSTOR {serial}",
                        event_type="USB Device Connected",
                        target_path=friendly or dev_key.name,
                        machine_id=machine_id,
                        details={"serial_number": serial,
                                 "vendor": vendor,
                                 "product": product,
                                 "revision": rev,
                                 "timestamp_source": "key_lastwrite"},
                        raw_bytes=b""))
    mounted = _get_key(hive, "\\MountedDevices")
    if mounted is None:
        notes.append("no MountedDevices key")
    else:
        stamp = _key_time_iso(mounted)
        for value in mounted.iter_values():
            name = value.name or ""
            raw = _reg_bytes(value)
            if raw is None:
                continue
            device, kind = name, "volume"
            if name.startswith("\\DosDevices\\"):
                device, kind = name[len("\\DosDevices\\"):], "drive_letter"
            detail_path, method = _decode_mounted(raw)
            records.append(make_record(
                timestamp_utc=stamp,
                timestamp_raw=stamp,
                source_file=sys_path,
                record_ref=f"MountedDevices\\{name}",
                parser="tier1_usb",
                parser_version=VERSION,
                source="USB",
                artifact_type="mounted_device",
                artifact_name=f"Mounted {device}",
                event_type="Volume Mounted",
                target_path=device,
                machine_id=machine_id,
                details={"device_path": detail_path,
                         "decode_method": method,
                         "mount_kind": kind,
                         "timestamp_source": "key_lastwrite"},
                raw_bytes=raw))
    if not records and not notes:
        notes.append("no USB history recovered")
    return records, notes


def _decode_mounted(raw):
    try:
        text = bytes(raw).decode("ascii")
        if text.startswith("DMIO:ID:"):
            return text[len("DMIO:ID:"):], "dmio_id"
    except (ValueError, OverflowError):
        pass
    display = _utf16_prefix(raw, limit=160)
    if display:
        return display, "utf16_path"
    return bytes(raw).hex()[:128], "raw_hex"


def collect_amcache(paths, machine_id=None):
    _require_regipy()
    hive_path = os.path.join(paths.windows, "appcompat", "Programs", "Amcache.hve")
    try:
        hive = _open_hive(hive_path)
    except Tier1Error as exc:
        return [], [str(exc)]
    root = _get_key(hive, "\\Root\\InventoryApplicationFile")
    if root is None:
        return [], ["Amcache has no InventoryApplicationFile"]
    records, notes = [], []
    for entry in root.iter_subkeys():
        values = {}
        for value in entry.iter_values():
            values[value.name] = value.value

        def pick(*names):
            for name in names:
                hit = values.get(name)
                if isinstance(hit, str) and hit:
                    return hit
            return None

        path = pick("LowerCaseLongPath", "LongPath")
        if path is None:
            for hit in values.values():
                if isinstance(hit, str) and PATH_RE.search(hit):
                    path = hit
                    break
        sha1 = None
        for hit in values.values():
            if isinstance(hit, str):
                found = SHA1_RE.search(hit)
                if found:
                    sha1 = found.group(0).lower()
                    break
        link_raw = pick("LinkDate")
        link_iso, link_method = None, None
        if link_raw:
            for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%y %H:%M:%S",
                        "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
                try:
                    naive = dt.datetime.strptime(link_raw.strip(), fmt)
                    link_iso = naive.replace(
                        tzinfo=dt.timezone.utc).isoformat()
                    link_method = "link_date"
                    break
                except ValueError:
                    continue
        stamp = link_iso or _key_time_iso(entry)
        method = link_method or "key_lastwrite"
        name = pick("Name") or entry.name.split("|")[0]
        records.append(make_record(
            timestamp_utc=stamp,
            timestamp_raw=link_raw or stamp,
            source_file=hive_path,
            record_ref=f"InventoryApplicationFile\\{entry.name}",
            parser="tier1_amcache",
            parser_version=VERSION,
            source="Amcache",
            artifact_type="amcache_file",
            artifact_name=f"Amcache {name}",
            event_type="Program Executed",
            target_path=path or name,
            machine_id=machine_id,
            details={"program": pick("ProductName"),
                     "publisher": pick("Publisher"),
                     "version": pick("Version", "BinFileVersion"),
                     "binary_type": pick("BinaryType"),
                     "sha1_candidate": sha1,
                     "size": values.get("Size") if isinstance(
                         values.get("Size"), int) else None,
                     "timestamp_source": method},
            raw_bytes=b""))
    if not records:
        notes.append("no InventoryApplicationFile entries recovered")
    return records, notes


# --------------------------------------------------------------------------
# collection dispatch (file-backed artifacts)
# --------------------------------------------------------------------------

def collect_prefetch(paths, machine_id=None):
    if parse_prefetch_file is None or iter_pf_files is None:
        return [], ["prefetch_parser module unavailable"]
    records, notes, skipped = [], [], 0
    target = os.path.join(paths.windows, "Prefetch")
    if not os.path.isdir(target):
        return [], [f"Prefetch directory absent: {target}"]
    for path in iter_pf_files(target, recursive=False):
        try:
            records.extend(parse_prefetch_at(path, machine_id=machine_id))
        except Exception as exc:  # noqa: BLE001 - per-file resilience
            skipped += 1
            notes.append(f"{os.path.basename(path)}: skipped ({exc})")
    if skipped:
        notes.insert(0, f"{skipped} Prefetch file(s) skipped")
    if not records and not notes:
        notes.append("no Prefetch files found")
    return records, notes


def collect_lnk(paths, machine_id=None):
    if parse_lnk_builtin is None or iter_lnk_files is None:
        return [], ["lnk_forensics module unavailable"]
    records, notes, skipped = [], [], 0
    found_any = False
    for user in paths.users:
        recent = os.path.join(user, "AppData", "Roaming", "Microsoft",
                              "Windows", "Recent")
        if not os.path.isdir(recent):
            continue
        found_any = True
        for path in iter_lnk_files(recent, recursive=False):
            try:
                records.extend(parse_lnk_at(path, machine_id=machine_id))
            except Exception as exc:  # noqa: BLE001
                skipped += 1
                notes.append(f"{os.path.basename(path)}: skipped ({exc})")
    if skipped:
        notes.insert(0, f"{skipped} LNK file(s) skipped")
    if not found_any:
        notes.append("no Recent directories found")
    elif not records and not notes:
        notes.append("no LNK files found")
    return records, notes


def collect_jumplist(paths, machine_id=None):
    if parse_jumplist_file is None or iter_jumplist_files is None:
        return [], ["jumplists_parser module unavailable"]
    records, notes, skipped = [], [], 0
    found_any = False
    for user in paths.users:
        recent = os.path.join(user, "AppData", "Roaming", "Microsoft",
                              "Windows", "Recent")
        for sub in ("AutomaticDestinations", "CustomDestinations"):
            folder = os.path.join(recent, sub)
            if not os.path.isdir(folder):
                continue
            found_any = True
            for path in iter_jumplist_files(folder, recursive=False):
                try:
                    records.extend(parse_jumplist_at(path, machine_id=machine_id))
                except Exception as exc:  # noqa: BLE001
                    skipped += 1
                    notes.append(f"{os.path.basename(path)}: skipped ({exc})")
    if skipped:
        notes.insert(0, f"{skipped} JumpList file(s) skipped")
    if not found_any:
        notes.append("no JumpList directories found")
    elif not records and not notes:
        notes.append("no JumpList files found")
    return records, notes


# --------------------------------------------------------------------------
# engine
# --------------------------------------------------------------------------

def available():
    """Per-artifact availability: (ok, reason). Registry ones need regipy."""
    table = {}
    for item in TIER1:
        if item["needs_regipy"] and RegistryHive is None:
            table[item["id"]] = (False, "needs: pip install regipy")
        else:
            table[item["id"]] = (True, "")
    if parse_prefetch_file is None:
        table["prefetch"] = (False, "prefetch_parser module unavailable")
    if parse_lnk_builtin is None:
        table["lnk"] = (False, "lnk_forensics module unavailable")
    if parse_jumplist_file is None:
        table["jumplist"] = (False, "jumplists_parser module unavailable")
    return table


class AcquisitionEngine:
    """Runs selected Tier 1 collectors with dedup and per-artifact reporting."""

    def __init__(self, evidence_root=None, machine_id=None):
        self.paths = Paths(evidence_root)
        self.machine_id = machine_id

    def run(self, selected, progress=None):
        """Returns (records, report). records sorted, deduped, strict+timeline."""
        wanted = [a for a in TIER1_IDS if a in set(selected or [])]
        avail = available()
        records, report, seen = [], {}, set()
        for item in TIER1:
            artifact = item["id"]
            if artifact not in wanted:
                continue
            if progress is not None:
                progress(item["label"])
            ok, reason = avail.get(artifact, (False, "unknown artifact"))
            if not ok:
                report[artifact] = {"status": "unavailable", "count": 0,
                                    "note": reason}
                continue
            try:
                if artifact in ("prefetch", "lnk", "jumplist"):
                    recs, notes = globals()[f"collect_{artifact}"](
                        self.paths, self.machine_id)
                elif artifact in ("userassist", "mru", "bam", "usb", "amcache"):
                    recs, notes = globals()[f"collect_{artifact}"](
                        self.paths, self.machine_id)
                else:
                    recs, notes = globals()[f"collect_{artifact}"](self.paths)
            except Tier1Error as exc:
                report[artifact] = {"status": "failed", "count": 0,
                                    "note": str(exc)}
                continue
            except Exception as exc:  # noqa: BLE001 - one artifact never kills a run
                report[artifact] = {"status": "failed", "count": 0,
                                    "note": f"{type(exc).__name__}: {exc}"}
                continue
            fresh, dups = [], 0
            for rec in recs:
                digest = rec.get("source_hash") or record_identity(
                    rec.get("source"), rec.get("source_file"),
                    rec.get("timestamp_utc"), rec.get("event_type"),
                    rec.get("target_path"))
                if digest in seen:
                    dups += 1
                    continue
                seen.add(digest)
                fresh.append(rec)
            status = "ok" if fresh else ("empty" if not notes else "ok")
            note = "; ".join(notes)
            if dups:
                note = ((note + "; ") if note else "") + f"{dups} duplicate(s) skipped"
            report[artifact] = {"status": status, "count": len(fresh), "note": note}
            records.extend(fresh)
        records.sort(key=lambda r: (r.get("timestamp_utc") is None,
                                    r.get("timestamp_utc") or ""))
        return records, report


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog=TOOL, description="Acquire Tier 1 forensic artifacts into a "
                               "unified, deduped JSON timeline.")
    parser.add_argument("evidence_root", nargs="?", default=None,
                        help="evidence root (offline image/triage layout); "
                             "omit for the live host")
    parser.add_argument("-o", "--output", default="tier1_timeline.json",
                        help="output JSON file (default: tier1_timeline.json)")
    parser.add_argument("--only", default=None,
                        help="comma-separated artifact ids (default: all)")
    parser.add_argument("--machine-id", default=None,
                        help="host identifier stamped when artifacts carry none")
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args(argv)

    selected = [s.strip().lower() for s in args.only.split(",")] if args.only else TIER1_IDS
    engine = AcquisitionEngine(args.evidence_root, args.machine_id)
    records, report = engine.run(selected)

    document = {
        "metadata": {
            "tool": TOOL,
            "version": VERSION,
            "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "evidence_root": engine.paths.root,
            "parser_engine": ["tier1", "regipy" if RegistryHive else "stdlib"],
            "timestamps_format": "ISO 8601 UTC",
            "machine_id": args.machine_id,
            "counts": {
                "timeline_events": len(records),
                "by_artifact": {k: v["count"] for k, v in report.items()},
            },
            "acquisition_report": report,
        },
        "events": records,
        "artifacts": [],
        "skipped": [],
    }
    with open(os.path.abspath(args.output), "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    if not args.quiet:
        for artifact, info in report.items():
            extra = f" ({info['note']})" if info["note"] else ""
            print(f"[{artifact}] {info['status']}: {info['count']} events{extra}")
        print(f"[+] {len(records)} events -> {os.path.abspath(args.output)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
