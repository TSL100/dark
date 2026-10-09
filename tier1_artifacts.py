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
  amcache     Amcache.hve (Win10 InventoryApplicationFile + legacy Win7/8
              Root\\File + Programs + orphan/copied hives; needs regipy)
  userassist  NTUSER.DAT UserAssist keys (needs regipy)
  bam         SYSTEM hive BAM keys (needs regipy)
  lnk         %AppData%\\...\\Recent\\*.lnk (reuses lnk_forensics)
  jumplist    Recent\\AutomaticDestinations (+Custom) (reuses jumplists_parser)
  recyclebin  $Recycle.Bin\\$I* files (pure struct parsing)
  zoneid      Zone.Identifier ADS on Recent/Desktop/Downloads files
  usb         SYSTEM USBSTOR + MountedDevices (needs regipy)
  mru         NTUSER.DAT RecentDocs/RunMRU/TypedPaths/OpenSaveMRU (needs regipy)
  shellbag    NTUSER.DAT BagMRU/Bags folder-browsing history, all four
              classic + Local Settings roots (reuses shellbag_parser)
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
  path matches are labeled with sha1_source = value/key_name; sizes accept
  int/decimal/0x-hex/bare-hex/bytes; timestamps carry filetime_pair /
  link_date / install_date / key_lastwrite as timestamp_source).
* Timestamps always carry timestamp_source (destlist_last_access,
  lnk_target_modification, key_lastwrite, file_mtime, ...).
* raw_binary_hex holds full bytes under 4 KiB, else the first 512 bytes with
  details.raw_truncated=true.
* There is no Machine SID in any of these artifacts; host correlation uses
  NetBIOS names, volume serials, DROID GUIDs and USB serials.

Dependencies: Python 3.8+ stdlib only, plus OPTIONAL regipy (pip install
regipy) for the six registry-backed artifacts. The four file/deep parsers
are reused from this directory; nothing else is required.
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
import shutil
import struct
import subprocess
import sys
import tempfile

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
# Amcache hive-walking helpers live here (not in a wrapper package) so the
# Run Analysis engine and any direct caller share identical values.
try:
    import shellbag_parser
    from shellbag_parser import iter_shellbag_entries
    SB_VERSION = getattr(shellbag_parser, "VERSION", "1.0.0")
except ImportError:  # pragma: no cover
    iter_shellbag_entries = None
    SB_VERSION = "1.0.0"

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
    {"id": "shellbag", "label": "Shellbags", "needs_regipy": True},
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


def _open_hive(path, notes=None):
    _require_regipy()
    if not os.path.isfile(path):
        raise Tier1Error(f"hive not present: {path}")
    try:
        return RegistryHive(path)
    except Tier1Error:
        raise
    except Exception as exc:  # locked / corrupt / unreadable
        snap = _snapshot_hive_via_reg(
            path, notes if notes is not None else [])
        if snap is not None:
            try:
                return RegistryHive(snap)
            except Exception as exc2:
                raise Tier1Error(
                    f"cannot open hive {path} (locked; snapshot failed: {exc2})")
        raise Tier1Error(f"cannot open hive {path} ({exc}). "
                         f"Live hives are locked; analyze an offline image or "
                         f"a triage copy (e.g. via `reg save`).")


_TEMP_HIVES: list[str] = []


def _drop_quietly(path):
    try:
        os.remove(path)
    except OSError:
        pass


def cleanup_temp_hives():
    for tmp in _TEMP_HIVES:
        _drop_quietly(tmp)
    _TEMP_HIVES.clear()


def _current_usernames():
    """Candidate names for the current interactive profile (plural: the
    USERNAME env var and the profile folder name often disagree)."""
    names = set()
    for var in ("USERNAME", "USER"):
        value = os.environ.get(var)
        if value:
            names.add(value.lower())
    try:
        home_base = os.path.basename(os.path.abspath(os.path.expanduser("~")))
        if home_base:
            names.add(home_base.lower())
    except Exception:
        pass
    return names


_PROFILE_SIDS: dict[str, str] | None = None


def _profile_sid_map() -> dict[str, str]:
    """Map normcased profile directory -> SID (live host, via `reg query`)."""
    global _PROFILE_SIDS
    if _PROFILE_SIDS is not None:
        return _PROFILE_SIDS
    _PROFILE_SIDS = {}
    if os.name != "nt" or shutil.which("reg") is None:
        return _PROFILE_SIDS
    try:
        proc = subprocess.run(
            ["reg", "query",
             r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
             "/s", "/v", "ProfileImagePath"],
            capture_output=True, timeout=60)
    except Exception:
        return _PROFILE_SIDS
    current_sid: str | None = None
    marker = "PROFILELIST\\"
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        text = line.strip()
        if text.upper().startswith("HKEY"):
            idx = text.upper().find(marker)
            current_sid = (text[idx + len(marker):].split("\\")[0]
                           if idx >= 0 else None)
        elif "ProfileImagePath" in text and current_sid:
            parts = text.split(None, 2)
            if len(parts) >= 3:
                profile = os.path.expandvars(parts[2].strip())
                _PROFILE_SIDS[os.path.normcase(profile)] = current_sid
            current_sid = None
    return _PROFILE_SIDS


def _snapshot_hive_via_reg(path, notes):
    """Read a locked live hive through a `reg save` snapshot.

    Only for unambiguous live mappings (HKLM\\SYSTEM, current-user HKCU).
    Returns the temp snapshot path (tracked for cleanup) or None when the
    fallback does not apply. Parsing itself stays pure-Python (regipy).
    """
    if os.name != "nt" or shutil.which("reg") is None:
        return None
    norm = os.path.normcase(os.path.abspath(path))
    key = None
    if norm.endswith(os.path.normcase(os.path.join("System32", "config", "SYSTEM"))):
        key = r"HKLM\SYSTEM"
    elif os.path.basename(path).upper() == "NTUSER.DAT":
        profile_dir = os.path.dirname(os.path.abspath(path))
        if os.path.basename(profile_dir).lower() in _current_usernames():
            key = "HKCU"
        else:
            # another user's locked profile: snapshot via HKU\<SID>
            sid = _profile_sid_map().get(os.path.normcase(profile_dir))
            if sid:
                key = f"HKU\\{sid}"
    if key is None:
        return None
    fd, tmp = tempfile.mkstemp(prefix="tier1_", suffix=".hiv")
    os.close(fd)
    try:
        proc = subprocess.run(["reg", "save", key, tmp, "/y"],
                              capture_output=True, timeout=240)
    except Exception:
        _drop_quietly(tmp)
        return None
    if proc.returncode != 0 or not os.path.isfile(tmp) or os.path.getsize(tmp) == 0:
        _drop_quietly(tmp)
        return None
    _TEMP_HIVES.append(tmp)
    notes.append(f"{os.path.basename(path)} is locked live; parsed a "
                 f"`reg save {key}` snapshot instead (temp copy auto-removed)")
    return tmp


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

def _iter_ntuser_keys(paths, failures=None):
    """Return (user, ntuser_path, RegistryHive, note) for readable NTUSER.DATs.

    Profiles that cannot be opened are collected in *failures* instead of
    aborting the whole run; Tier1Error is raised only when no hive at all
    could be opened.
    """
    _require_regipy()
    errors = failures if failures is not None else []
    opened: list[tuple] = []
    for user in paths.users:
        hive_path = os.path.join(user, "NTUSER.DAT")
        if not os.path.isfile(hive_path):
            continue
        notes: list[str] = []
        try:
            opened.append((user, hive_path, _open_hive(hive_path, notes),
                           (notes[0] if notes else None)))
        except Tier1Error as exc:
            errors.append(f"cannot open {hive_path}: {exc}")
    if not opened and errors:
        raise Tier1Error("; ".join(errors))
    return opened


def collect_userassist(paths, machine_id=None):
    _require_regipy()
    base = ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    records, notes, skipped = [], [], 0
    failures: list[str] = []
    try:
        hives = _iter_ntuser_keys(paths, failures)
    except Tier1Error as exc:
        return [], [str(exc)]
    if not hives:
        return [], ["no readable NTUSER.DAT found"]
    notes.extend(failures)
    for user, hive_path, hive, hive_note in hives:
        if hive_note:
            notes.append(hive_note)
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
    failures: list[str] = []
    try:
        hives = _iter_ntuser_keys(paths, failures)
    except Tier1Error as exc:
        return [], [str(exc)]
    if not hives:
        return [], ["no readable NTUSER.DAT found"]
    notes.extend(failures)
    for user, hive_path, hive, hive_note in hives:
        if hive_note:
            notes.append(hive_note)
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


def collect_shellbag(paths, machine_id=None):
    """BagMRU/Bags folder-browsing history (four roots per user hive).

    Entry timestamps come from the child folder's bag LastWrite (the
    moment Explorer last wrote that folder's view), falling back to the
    parent bag, the key LastWrite or the shell item's FAT dates - always
    labeled in details.timestamp_source.
    """
    _require_regipy()
    if iter_shellbag_entries is None:
        return [], ["shellbag_parser module unavailable"]
    records, notes = [], []
    failures: list[str] = []
    try:
        hives = _iter_ntuser_keys(paths, failures)
    except Tier1Error as exc:
        return [], [str(exc)]
    if not hives:
        return [], ["no readable NTUSER.DAT found"]
    notes.extend(failures)
    for user, hive_path, hive, hive_note in hives:
        if hive_note:
            notes.append(hive_note)
        who = os.path.basename(user)
        count = 0
        try:
            entries = iter_shellbag_entries(hive)
            for entry in entries:
                stamp = entry.get("timestamp")
                if not stamp:
                    continue
                records.append(make_record(
                    timestamp_utc=stamp,
                    timestamp_raw=stamp,
                    source_file=hive_path,
                    record_ref=entry.get("record_ref") or "BagMRU",
                    parser="tier1_shellbag",
                    parser_version=SB_VERSION,
                    source="Shellbag",
                    artifact_type="shellbag_entry",
                    artifact_name=entry.get("name") or _base(entry.get("path")),
                    event_type="Folder Browsed",
                    target_path=entry.get("path"),
                    machine_id=machine_id,
                    details={"user": who,
                             "root": entry.get("root"),
                             "bag_slot": entry.get("bag_slot"),
                             "timestamp_source": entry.get("timestamp_source"),
                             "item_mtime": entry.get("item_mtime"),
                             "item_type": entry.get("item_type"),
                             "deleted": False,
                             "renamed": False},
                    raw_bytes=entry.get("raw") or b""))
                count += 1
        except Exception as exc:  # noqa: BLE001 - one bad hive never kills a run
            notes.append(f"{who}: shellbag walk failed ({exc})")
            continue
        if not count:
            notes.append(f"{who}: no shellbag entries recovered")
    if not records and not notes:
        notes.append("no shellbag entries recovered")
    return records, notes


def collect_bam(paths, machine_id=None):
    _require_regipy()
    sys_path = os.path.join(paths.windows, "System32", "config", "SYSTEM")
    records, notes = [], []
    try:
        hive = _open_hive(sys_path, notes)
    except Tier1Error as exc:
        return [], [str(exc)]
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
    records, notes = [], []
    try:
        hive = _open_hive(sys_path, notes)
    except Tier1Error as exc:
        return [], [str(exc)]
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


AMCACHE_HIVE_LIMIT = 10
AMCACHE_HIVE_DEPTH = 7


def _find_amcache_hives(paths, standard):
    """Standard path first, then orphan/copied hives (incl. VSS copies).

    Orphan search only runs for an evidence root (offline image / triage
    folder); walking a live system drive is never attempted.
    """
    candidates, seen = [], set()
    if os.path.isfile(standard):
        seen.add(os.path.normcase(os.path.abspath(standard)))
        candidates.append(standard)
    if not paths.root:
        return candidates
    base = os.path.abspath(paths.root)
    for dirpath, dirnames, filenames in os.walk(base):
        if os.path.relpath(dirpath, base).count(os.sep) >= AMCACHE_HIVE_DEPTH:
            dirnames[:] = []
        for fname in filenames:
            low = fname.lower()
            ext = os.path.splitext(fname)[1].lower()
            if not (low.startswith("amcache") and ext in (".hve", "")):
                continue
            full = os.path.join(dirpath, fname)
            norm = os.path.normcase(os.path.abspath(full))
            if norm in seen:
                continue
            seen.add(norm)
            candidates.append(full)
            if len(candidates) >= AMCACHE_HIVE_LIMIT:
                return candidates
    return candidates


# --------------------------------------------------------------------------
# Amcache hive-walking helpers (multi-generation extraction)
#
# Supported layouts (all under the hive ``Root`` key):
# * ``InventoryApplicationFile`` - Windows 10 1703+ (current format)
# * ``File``                    - legacy Windows 7/8/8.1 format
# * ``Programs``                - early Windows 10 / 8.1 application rows
#
# Every extraction path handles SHA-1 (``SHA1``/``FileId`` values or the
# legacy key name), Size (ints, decimal/hex strings, LE byte blobs) and
# timestamps (``LowDateTime``/``HighDateTime`` FILETIME pairs,
# ``LinkDate``/``InstallDate`` strings, key LastWrite fallback).
# --------------------------------------------------------------------------

#: (registry section name, internal section id)
_FILE_SECTIONS = (("InventoryApplicationFile", "inventory_file"),
                  ("File", "legacy_file"))
_PROGRAM_SECTIONS = (("Programs", "program"),)

SECTION_EVENT = {
    "inventory_file": "Program Executed",
    "legacy_file": "Program Executed",
    "program": "Program Installed",
}

_DATE_FORMATS = (
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y%m%d",
    "%Y-%m-%d",
    "%d/%m/%Y %H:%M:%S",
)


def parse_size(value):
    """Registry size values arrive as int, decimal str, hex str or bytes."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if 0 < len(raw) <= 8:
            return int.from_bytes(raw, "little")
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            if text.lower().startswith("0x"):
                return int(text, 16)
            if text.isdigit():
                return int(text, 10)
            if re.fullmatch(r"[0-9a-fA-F]+", text) and re.search(r"[a-fA-F]", text):
                return int(text, 16)
        except ValueError:
            return None
    return None


def _text(value):
    """Decode a registry value to clean text (handles UTF-16LE blobs)."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if not raw:
            return ""
        if b"\x00" in raw:
            text = raw.decode("utf-16-le", "ignore").strip("\x00").strip()
            if text and sum(ch.isprintable() for ch in text) / len(text) > 0.8:
                return text
        for encoding in ("utf-8", "latin-1"):
            text = raw.decode(encoding, "ignore").strip("\x00").strip()
            if text:
                return text
        return ""
    return str(value).strip()


def _pick(values, *names):
    for name in names:
        text = _text(values.get(name))
        if text:
            return text
    return None


def _path_text(value):
    """Path extraction that also handles bytes and regipy hex-string binaries.

    regipy renders some REG_BINARY values (legacy FullPath) as hex strings,
    not bytes; those are decoded back through UTF-16LE/UTF-8 and validated
    with PATH_RE before use. ``\\??\\`` prefixes are stripped.
    """
    def clean(text):
        if text.startswith("\\??\\"):
            text = text[4:]
        return text if text and PATH_RE.search(text) else ""

    text = clean(_text(value))
    if text:
        return text
    raw = None
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, str):
        blob = value.strip()
        if blob and len(blob) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", blob):
            try:
                raw = bytes.fromhex(blob)
            except ValueError:
                raw = None
    if not raw:
        return ""
    for encoding in ("utf-16-le", "utf-8"):
        try:
            decoded = raw.decode(encoding).strip("\x00").strip()
        except UnicodeDecodeError:
            continue
        cleaned = clean(decoded)
        if cleaned:
            return cleaned
    return ""


def _pick_path(values, *names):
    for name in names:
        if name not in values:
            continue
        text = _path_text(values[name])
        if text:
            return text
    return None


def _iso_from_string(text):
    """Best-effort parse of date strings written by different Amcache gens."""
    cleaned = text.strip()
    if not cleaned:
        return None
    for fmt in _DATE_FORMATS:
        try:
            moment = dt.datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
        return moment.replace(tzinfo=dt.timezone.utc).isoformat()
    try:
        moment = dt.datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return moment.isoformat()


def _filetime_pair(values):
    """Win7/8 stores the clock as REG_DWORD HighDateTime/LowDateTime."""
    low = values.get("LowDateTime")
    high = values.get("HighDateTime")
    if low is None or high is None:
        return None
    try:
        combined = ((int(high) & 0xFFFFFFFF) << 32) | (int(low) & 0xFFFFFFFF)
    except (TypeError, ValueError):
        return None
    if combined <= 0:
        return None
    try:
        moment = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(
            microseconds=combined // 10)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.isoformat()


def _key_time(key_obj):
    """Key LastWrite — the fallback clock for every Amcache generation."""
    try:
        value = key_obj.header.last_modified
    except AttributeError:
        return None
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc).isoformat()
    if isinstance(value, int) and value > 0:
        try:
            moment = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(
                microseconds=value // 10)
        except (OverflowError, OSError, ValueError):
            return None
        return moment.isoformat()
    return None


def _sha1_of(values, key_name):
    """SHA-1 from named values first, then any value, then the key name."""
    ordered = [values.get("SHA1"), values.get("Sha1"), values.get("FileId")]
    ordered += [v for v in values.values() if v not in ordered]
    for raw in ordered:
        text = _text(raw)
        if not text:
            continue
        found = SHA1_RE.search(text)
        if found:
            source = "value" if raw in (values.get("SHA1"), values.get("Sha1"),
                                        values.get("FileId")) else "value_scan"
            return found.group(0).lower(), source
    found = SHA1_RE.search(key_name or "")
    if found:
        return found.group(0).lower(), "key_name"
    return None, None


def _entry_from_subkey(section, kind, key):
    values = {}
    try:
        for value in key.iter_values():
            values[value.name] = value.value
    except Exception:  # corrupt value table — keep what we have
        pass

    key_name = key.name or ""

    path = _pick_path(values, "LowerCaseLongPath", "LongPath", "FullPath",
                      "Path", "RootDirPath")
    if not path:
        for candidate in values.values():
            text = _path_text(candidate)
            if text:
                path = text
                break

    name = _pick(values, "Name", "OriginalFileName", "DisplayName",
                 "ProgramName")
    if not name and path:
        name = ntpath.basename(path) or None
    if not name and "|" in key_name:
        name = key_name.split("|", 1)[0]
    if not name:
        name = key_name or "Unknown"

    sha1, sha1_source = _sha1_of(values, key_name)
    size = parse_size(values.get("Size"))
    if size is None:
        size = parse_size(values.get("FileSize"))

    program_id = _pick(values, "ProgramId")

    # ---- timestamp -----------------------------------------------------
    stamp = stamp_raw = None
    stamp_source = "key_lastwrite"
    if kind != "program":
        pair = _filetime_pair(values)
        if pair:
            stamp, stamp_source = pair, "filetime_pair"
        else:
            link = _pick(values, "LinkDate", "Link date")
            if link:
                stamp = _iso_from_string(link)
                if stamp:
                    stamp_raw, stamp_source = link, "link_date"
    if stamp is None and kind == "program":
        install = _pick(values, "InstallDate", "InstallDate2", "Installed")
        if install:
            stamp = _iso_from_string(install)
            if stamp:
                stamp_raw, stamp_source = install, "install_date"
    if stamp is None:
        stamp = _key_time(key)
        stamp_source = "key_lastwrite"

    return {
        "section": kind,
        "section_name": section,
        "key_name": key_name,
        "key_ref": f"Root\\{section}\\{key_name}",
        "path": path,
        "name": name,
        "sha1": sha1,
        "sha1_source": sha1_source,
        "size": size,
        "stamp": stamp,
        "stamp_raw": stamp_raw,
        "stamp_source": stamp_source,
        "program": _pick(values, "ProductName", "DisplayName", "ProgramName"),
        "publisher": _pick(values, "Publisher"),
        "version": _pick(values, "Version", "BinFileVersion", "ProductVersion"),
        "binary_type": _pick(values, "BinaryType"),
        "program_id": program_id,
    }


def iter_hive_entries(hive):
    """Yield normalised entries from an OPEN regipy Amcache hive.

    Walks every supported section (InventoryApplicationFile, legacy File,
    Programs) and returns dicts ready for Tier 1 ``make_record`` adapters.
    """
    for section, kind in _FILE_SECTIONS + _PROGRAM_SECTIONS:
        try:
            root_key = hive.get_key("\\Root\\" + section)
        except Exception:
            root_key = None
        if root_key is None:
            continue
        try:
            subkeys = list(root_key.iter_subkeys())
        except Exception:
            continue
        for sub in subkeys:
            try:
                yield _entry_from_subkey(section, kind, sub)
            except Exception:  # one bad row never kills the section
                continue


def _amcache_record(entry, hive_path, machine_id):
    """Adapt one shared Amcache entry dict to a record."""
    details = {
        "section": entry["section"],
        "timestamp_source": entry["stamp_source"],
        "sha1": entry["sha1"],
        "sha1_source": entry["sha1_source"],
        "size": entry["size"],
        "program": entry["program"],
        "publisher": entry["publisher"],
        "version": entry["version"],
        "binary_type": entry["binary_type"],
        "program_id": entry["program_id"],
    }
    details = {k: v for k, v in details.items() if v is not None}
    name = entry["name"] or "Unknown"
    return make_record(
        timestamp_utc=entry["stamp"],
        timestamp_raw=entry["stamp_raw"] or entry["stamp"],
        source_file=hive_path,
        record_ref=entry["key_ref"],
        parser="tier1_amcache",
        parser_version=VERSION,
        source="Amcache",
        artifact_type=("amcache_program" if entry["section"] == "program"
                       else "amcache_file"),
        artifact_name=f"Amcache {name}",
        event_type=(SECTION_EVENT or {}).get(entry["section"],
                                             "Program Executed"),
        target_path=entry["path"] or name,
        machine_id=machine_id,
        details=details,
        raw_bytes=b"")


def collect_amcache(paths, machine_id=None):
    """Collect Amcache from every generation and hive copy under *paths*.

    Covers Win10 1703+ ``InventoryApplicationFile``, legacy Win7/8
    ``Root\\File``, the ``Programs`` key, and orphan/copied ``Amcache*``
    hives anywhere under an evidence root (deduplicated across copies).
    """
    _require_regipy()
    records, notes = [], []
    standard = os.path.join(paths.windows, "appcompat", "Programs",
                            "Amcache.hve")
    candidates = _find_amcache_hives(paths, standard)
    if not candidates:
        scope = f" (standard path and {paths.root})" if paths.root else ""
        return [], [f"Amcache.hve not found{scope}"]
    if len(candidates) > 1:
        notes.append(f"{len(candidates)} Amcache hive copy(ies) found "
                     "(standard + orphan/VSS copies); deduplicated across "
                     "copies")
    opened = 0
    seen_hashes = set()
    standard_norm = os.path.normcase(os.path.abspath(standard))
    for hive_path in candidates:
        hive_notes: list[str] = []
        try:
            hive = _open_hive(hive_path, hive_notes)
        except Tier1Error as exc:
            notes.append(f"{hive_path}: {exc}")
            continue
        opened += 1
        notes.extend(hive_notes)
        before = len(records)
        for entry in iter_hive_entries(hive):
            rec = _amcache_record(entry, hive_path, machine_id)
            if rec["source_hash"] in seen_hashes:
                continue
            seen_hashes.add(rec["source_hash"])
            records.append(rec)
        added = len(records) - before
        is_standard = (os.path.normcase(os.path.abspath(hive_path))
                       == standard_norm)
        tag = "Amcache.hve" if is_standard else f"orphan {hive_path}"
        if added:
            notes.append(f"{tag}: {added:,} entries")
        else:
            notes.append(f"{tag}: no recognizable Amcache entries")
    if not opened:
        return [], notes
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
    if iter_shellbag_entries is None:
        table["shellbag"] = (False, "shellbag_parser module unavailable")
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
        cleanup_temp_hives()  # drop leftovers from interrupted runs
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
                elif artifact in ("userassist", "mru", "bam", "usb", "amcache",
                                  "shellbag"):
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
            status = "ok" if fresh else "empty"
            note = "; ".join(notes)
            if dups:
                note = ((note + "; ") if note else "") + f"{dups} duplicate(s) skipped"
            report[artifact] = {"status": status, "count": len(fresh), "note": note}
            records.extend(fresh)
        records.sort(key=lambda r: (r.get("timestamp_utc") is None,
                                    r.get("timestamp_utc") or ""))
        cleanup_temp_hives()  # snapshots are parsed; remove temp copies now
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
