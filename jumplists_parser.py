#!/usr/bin/env python3
"""
jumplists_parser.py - Windows Jump Lists parser -> chronological JSON timeline.

DFIR PoC engine, companion to lnk_forensics.py and prefetch_parser.py. Parses
Windows Jump Lists and emits the SAME standardized event/JSON schema with
source "JumpLists", so the existing PySide6 viewer ingests the output with no
format changes (a source-filter dropdown is added separately in the GUI).

Jump Lists complete the story told by LNK + Prefetch:
  LNK        -> a shortcut existed pointing at target X
  Prefetch   -> executable Y ran N times, last at T
  JumpLists  -> user opened specific internal file Z *inside* application A
                (recent / frequent / pinned per-AppID destinations)

Supported inputs
----------------
* ``*.automaticDestinations-ms`` -- OLE compound file (MS-CFB) holding one
  raw LNK per hex-numbered stream plus a ``DestList`` MRU stream (timestamps,
  access counts, pin state, NetBIOS host name). Parsed with the built-in
  dependency-free OLE reader below (regular FAT + MiniFAT backed).
* ``*.customDestinations-ms`` -- flat concatenation of raw LNK blobs (no
  length prefixes, no container timestamps). Entries are recovered by carving
  on the LNK signature + LinkCLSID and slicing between consecutive hits.

High-value fields per entry: internal target path (from the embedded LNK),
AppID + application name, DestList last-access time (automatic), access count,
pin state, NetBIOS hostname, volume/object GUIDs, and the embedded LNK's own
target timestamps / volume serial / machine id.

Each entry becomes one timeline event. Custom-destination entries carry no
container timestamp, so their event time falls back through the embedded
LNK's target modification/access/creation times (details.timestamp_source
records which one; entries with no usable time stay in the record but emit
no event -- never guessed).

Event schema (mirrors lnk_forensics / prefetch_parser events exactly)
---------------------------------------------------------------------
    {
      "timestamp": str,            # ISO 8601 UTC
      "timestamp_type": str,       # Jump List Accessed | Jump List Entry |
                                   # JumpList File Modified | JumpList File Created
      "source": "JumpLists",
      "artifact_type": "jumplists",
      "jumplists_file": str,       # e.g. 9b9cdc69c1c24e2b.automaticDestinations-ms
      "jumplists_path": str,       # absolute path
      "jumplists_name": str,       # alias read by the GUI normalizer
      "artifact_name": str,        # alias read by the GUI normalizer
      "appid": str,                # e.g. 9b9cdc69c1c24e2b
      "app_name": str|None,
      "target_path": str,          # the internal file opened in the app
      "details": {
        "appid": str, "app_name": str|None,
        "destinations_type": "automatic"|"custom",
        "entry_id": int|None, "stream_name": str|None,
        "checksum": "0x................"|None,
        "netbios_name": str|None, "access_count": float|None,
        "pinned": bool|None,
        "timestamp_source": str,   # destlist_last_access | lnk_target_* | file_mtime
        "lnk_target_creation/access/modification_utc": str|None,
        "lnk_volume_serial_number": str|None, "lnk_machine_id": str|None,
        "destlist_heuristic": bool, "machine_id": str|None,
        "parsers_used": [str, ...],
      },
    }

Usage:
    python jumplists_parser.py [PATH] [-o OUTPUT.json] [--flat] [--all]
                               [--machine-id HOST] [--appid-map AppIDs.txt]
                               [--strict] [-q]

Robustness policy (flexible by default, never inventing data)
-------------------------------------------------------------
* Short/truncated streams are read partially (noted) and still parsed --
  LNK decoding tolerates tail truncation, so early fields like the target
  path usually survive. Use --strict to restore fail-fast stream reads.
* Streams are attempted regardless of name (not just hex-numbered ones),
  and LNKs are carved even at nonzero stream offsets (offset recorded).
* Unknown DestList versions fall back to a *validated* heuristic walk that
  only keeps rows whose entry ID matches a real stream -- anything else is
  skipped, never emitted.
* Unknown filename suffixes are sniffed by content (OLE magic -> automatic,
  LNK signature -> custom) instead of being rejected outright.
* machine_id falls back CLI > DestList NetBIOS > embedded LNK TrackerData
  (source always noted).

Dependencies: Python 3.8+ standard library only. LNK decoding is reused from
lnk_forensics.parse_lnk_bytes (same directory); no pip packages required.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import struct
import sys

try:
    from lnk_forensics import parse_lnk_bytes
except ImportError:  # allow `python path/to/jumplists_parser.py` from anywhere
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from lnk_forensics import parse_lnk_bytes

TOOL = "jumplists_parser.py"
VERSION = "1.2.0"

FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
MAX_SANE_FILE = 64 * 1024 * 1024
OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
LNK_SIG = bytes.fromhex("4C000000") + bytes.fromhex("0114020000000000C000000000000046")

AUTO_SUFFIX = ".automaticdestinations-ms"
CUSTOM_SUFFIX = ".customdestinations-ms"

STREAM_NUMBER_RE = re.compile(r"^[0-9a-fA-F]+$")
# AppIDs are 16-hex CRC64s, but at least one real-world AppID (Paint's
# 12dc1ea8e34b5a6) is 15 chars, so accept 8..16 rather than drop evidence.
APPID_RE = re.compile(r"^[0-9a-fA-F]{8,16}$")

# Well-known AppIDs (AppID -> application). Lowercase keys. Unknown AppIDs are
# kept as-is with app_name None -- never guessed. Extend via --appid-map.
KNOWN_APPIDS = {
    "5f7b5f1e01b83767": "Quick Access (Windows Explorer)",
    "1b4dd67f29cb1962": "Windows Explorer Recent",
    "f01b4d95cf55d32a": "Windows Explorer",
    "9b9cdc69c1c24e2b": "Notepad (64-bit)",
    "918e0ecb43d17e23": "Notepad (32-bit)",
    "47592b67dd97a119": "Windows Notepad",
    "a7bd71699cd38d1c": "Microsoft Office Word 2010",
    "a4a5324453625195": "Microsoft Word 2013",
    "a18df73203b0340e": "Microsoft Word 2016",
    "a8c43ef36da523b1": "Microsoft Office Word 2003",
    "9d1f905ce5044aee": "Microsoft Excel",
    "b8ab77100df80ab2": "Microsoft Office Excel x64",
    "9839aec31243a928": "Microsoft Office Excel 2010",
    "cdf30b95c55fd785": "Microsoft Office Excel 2007",
    "d00655d2aa12ff6d": "Microsoft PowerPoint",
    "9c7cc110ff56d1bd": "Microsoft Office PowerPoint 2010",
    "5f6e7bc0fb699772": "Microsoft Office PowerPoint 2010 x64",
    "bc03160ee1a59fc1": "Outlook",
    "12dc1ea8e34b5a6": "Microsoft Paint",
    "7e4dca80246863e3": "Control Panel",
    "1cf97c38a5881255": "Microsoft Edge",
    "28c8b86deab549a1": "Internet Explorer",
    "290532160612e071": "WinRAR",
    "e70d383b15687e37": "Notepad++",
    "70ffd305907c983b": "7-Zip",
    "5fd959f6fe6b8ae7": "PuTTY",
    "f2a9149d1c88d093": "Tor Browser (Firefox)",
    "f1dfe90245a04467": "Media Player Classic (MPC-BE)",
    "5e4713eb935be0b1": "foobar2000",
    "69d97cdc8d4d5043": "Windows Mail / Communications",
    "271e609288e1210a": "Microsoft Office Access 2010",
    "1bc392b8e104a00e": "Remote Desktop",
}


# --------------------------------------------------------------------------
# errors + small binary helpers
# --------------------------------------------------------------------------

class JumpListParseError(ValueError):
    """Raised when a Jump List file is invalid, truncated, or unsupported."""


class OleError(JumpListParseError):
    """Raised when the OLE compound container itself is unreadable."""


def _u16(data, off):
    if off < 0 or off + 2 > len(data):
        raise JumpListParseError(f"unexpected end of data at offset 0x{off:X}")
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    if off < 0 or off + 4 > len(data):
        raise JumpListParseError(f"unexpected end of data at offset 0x{off:X}")
    return struct.unpack_from("<I", data, off)[0]


def _i32(data, off):
    if off < 0 or off + 4 > len(data):
        raise JumpListParseError(f"unexpected end of data at offset 0x{off:X}")
    return struct.unpack_from("<i", data, off)[0]


def _u64(data, off):
    if off < 0 or off + 8 > len(data):
        raise JumpListParseError(f"unexpected end of data at offset 0x{off:X}")
    return struct.unpack_from("<Q", data, off)[0]


def _f32(data, off):
    if off < 0 or off + 4 > len(data):
        raise JumpListParseError(f"unexpected end of data at offset 0x{off:X}")
    return struct.unpack_from("<f", data, off)[0]


def filetime_to_utc(value):
    if not value:
        return None
    try:
        return FILETIME_EPOCH + dt.timedelta(microseconds=value // 10)
    except (OverflowError, OSError, ValueError):
        return None


def iso(dtobj):
    return dtobj.astimezone(dt.timezone.utc).isoformat() if dtobj else None


def guid_mixed(raw):
    """16 raw bytes -> {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} (D1-D3 LE)."""
    if len(raw) != 16:
        return None
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    d4 = raw[8:10].hex().upper()
    d5 = raw[10:16].hex().upper()
    return f"{{{d1:08X}-{d2:04X}-{d3:04X}-{d4}-{d5}}}"


# --------------------------------------------------------------------------
# minimal OLE compound-file (MS-CFB) reader -- stdlib only
# --------------------------------------------------------------------------

_ENDOFCHAIN = 0xFFFFFFFE
_FREESECT = 0xFFFFFFFF


class OleReader:
    """Read streams from an OLE compound file (Jump Lists use 512B sectors).

    Supports regular FAT chains (with DIFAT continuation) and the MiniFAT /
    MiniStream path that small LNK streams live on. Strict about structure
    (magic, bounds, chain loops); tolerant about trailing sector slack.
    """

    def __init__(self, data):
        self.data = bytes(data)
        self.warnings = []  # non-fatal notes (short streams, slack, ...)
        if len(self.data) < 512 or self.data[:8] != OLE_MAGIC:
            raise OleError("missing OLE compound-file signature")
        self.sector_size = 1 << _u16(self.data, 30)
        self.mini_size = 1 << _u16(self.data, 32)
        if self.sector_size not in (512, 4096) or self.mini_size != 64:
            raise OleError(
                f"unsupported sector sizes ({self.sector_size}/{self.mini_size})")
        self.nsectors = (len(self.data) - 512 + self.sector_size - 1) // self.sector_size
        if self.nsectors <= 0:  # ceiling: the last sector may be partial
            raise OleError("file holds no sectors")
        self.mini_cutoff = _u32(self.data, 56)
        self.fat = self._load_fat()
        self.dir_entries = self._load_directory()
        mini_root = self.dir_entries[0]
        self.ministream = self._read_chain(
            mini_root["start"], self.fat, mini_root["size"], "MiniStream") \
            if mini_root["size"] else b""
        self.mini_fat = self._chain_to_list(
            _i32(self.data, 60), self.fat, _u32(self.data, 64),
            "MiniFAT", entry_size=4) if _u32(self.data, 64) else []

    # -- low-level sector access -------------------------------------------
    def _sector(self, index):
        if index < 0 or index >= self.nsectors:
            raise OleError(f"sector {index} out of range ({self.nsectors} sectors)")
        base = 512 + index * self.sector_size
        return self.data[base:base + self.sector_size]

    def _follow(self, start, fat, what):
        """Follow a FAT chain; returns list of sector indices (loop-guarded)."""
        if start in (_ENDOFCHAIN, _FREESECT):
            return []
        if start < 0 or start >= len(fat):
            raise OleError(f"{what}: bad start sector {start}")
        chain, seen, cur = [], set(), start
        while cur not in (_ENDOFCHAIN, _FREESECT):
            if cur in seen or cur < 0 or cur >= len(fat):
                raise OleError(f"{what}: corrupt chain at sector {cur}")
            if fat[cur] not in (_ENDOFCHAIN, _FREESECT) and \
                    (fat[cur] < 0 or fat[cur] >= len(fat)):
                raise OleError(f"{what}: chain points outside FAT ({fat[cur]})")
            seen.add(cur)
            chain.append(cur)
            if len(chain) > self.nsectors + 1:
                raise OleError(f"{what}: chain longer than the file")
            cur = fat[cur]
        return chain

    def _read_chain(self, start, fat, size, what):
        if size == 0:
            return b""
        blob = bytearray()
        for sector in self._follow(start, fat, what):
            blob += self._sector(sector)
            if len(blob) >= size:
                break
        # A chain shorter than declared size is tolerated: streams are cut.
        return bytes(blob[:size])

    def _chain_to_list(self, start, fat, count, what, entry_size):
        # NOTE: `count` is a sector count; every DWORD in those sectors is an
        # entry (a MiniFAT sector holds sector_size/4 next-pointers).
        if start in (_ENDOFCHAIN, _FREESECT) or count == 0:
            return []
        blob = self._read_chain(start, fat, count * self.sector_size, what)
        return [struct.unpack_from("<I", blob, i * entry_size)[0]
                for i in range(len(blob) // entry_size)]

    # -- FAT / directory ----------------------------------------------------
    def _load_fat(self):
        n_fat_sectors = _u32(self.data, 44)
        difat = [_u32(self.data, 76 + i * 4) for i in range(109)]
        difat = [s for s in difat if s not in (_FREESECT,)]
        sectors = []
        continuation = _u32(self.data, 68)  # unsigned: FE/FF = no continuation
        seen = set(difat)
        while continuation not in (_ENDOFCHAIN, _FREESECT):
            if continuation in seen or continuation < 0 or \
                    continuation >= self.nsectors:
                raise OleError("corrupt DIFAT continuation chain")
            seen.add(continuation)
            raw = self._sector(continuation)
            entries = len(raw) // 4
            for i in range(entries - 1):  # last DWORD chains onward
                sectors.append(struct.unpack_from("<I", raw, i * 4)[0])
            continuation = struct.unpack_from("<i", raw, (entries - 1) * 4)[0]
            if len(sectors) > self.nsectors + 109:
                raise OleError("DIFAT chain longer than the file")
        sectors = difat + [s for s in sectors if s not in (_FREESECT,)]
        if n_fat_sectors and len(sectors) > n_fat_sectors + 1:
            sectors = sectors[:n_fat_sectors]
        fat = []
        for sector in sectors:
            raw = self._sector(sector)
            for i in range(len(raw) // 4):
                fat.append(struct.unpack_from("<I", raw, i * 4)[0])
        if not fat:
            raise OleError("no FAT found")
        return fat

    def _load_directory(self):
        first = _i32(self.data, 48)
        if first in (_ENDOFCHAIN, _FREESECT):
            raise OleError("no directory chain")
        blob = self._read_chain(first, self.fat, self.nsectors * 128 + 128, "directory")
        entries = []
        for i in range(len(blob) // 128):
            e = blob[i * 128:(i + 1) * 128]
            name_len = struct.unpack_from("<H", e, 64)[0]
            if name_len == 0 or name_len > 64:
                entries.append(None)
                continue
            try:
                name = e[:name_len - 2].decode("utf-16-le")
            except (ValueError, OverflowError):
                entries.append(None)
                continue
            entries.append({
                "name": name,
                "type": e[66],  # 1 storage, 2 stream, 5 root
                "left": struct.unpack_from("<i", e, 68)[0],
                "right": struct.unpack_from("<i", e, 72)[0],
                "child": struct.unpack_from("<i", e, 76)[0],
                "start": struct.unpack_from("<i", e, 116)[0],
                "size": struct.unpack_from("<Q", e, 120)[0],
            })
        if not entries or entries[0] is None or entries[0]["type"] != 5:
            raise OleError("missing root storage entry")
        return entries

    # -- public API -----------------------------------------------------------
    def streams(self):
        """{stream name: (start, size)} for every stream under root storage."""
        found = {}

        def visit(node):
            if node in (None, -1) or node >= len(self.dir_entries):
                return
            entry = self.dir_entries[node]
            if entry is None:
                return
            visit(entry["left"])
            if entry["type"] == 2 and entry["name"] not in found:
                found[entry["name"]] = (entry["start"], entry["size"])
            if entry["type"] == 1:  # nested storage (not seen in the wild)
                visit(entry["child"])
            visit(entry["right"])

        visit(self.dir_entries[0]["child"])
        return found

    def read_stream(self, start, size, what="stream", strict=True):
        """Read a stream by (start, size); MiniStream path when small.

        With strict=False a short chain returns its partial bytes (logged to
        self.warnings) instead of raising -- the caller can still salvage
        early fields from truncated LNK streams.
        """
        if size == 0:
            return b""
        if size > MAX_SANE_FILE:
            raise OleError(f"{what}: implausible size {size}")
        if size < self.mini_cutoff:
            result = self._read_mini(start, size, what)
        else:
            result = self._read_chain(start, self.fat, size, what)
        if len(result) < size:  # short chains are corruption, not slack
            if strict:
                raise OleError(f"{what}: short stream ({len(result)} of {size} bytes)")
            self.warnings.append(
                f"{what}: short stream, parsing partial "
                f"({len(result)} of {size} bytes)")
        return result

    def _read_mini(self, start, size, what):
        if not self.mini_fat:
            raise OleError(f"{what}: MiniFAT missing for small stream")
        blob = bytearray()
        cur, seen = start, set()
        while cur not in (_ENDOFCHAIN, _FREESECT):
            if cur in seen or cur < 0 or cur * self.mini_size >= len(self.ministream):
                raise OleError(f"{what}: corrupt minifat chain at {cur}")
            seen.add(cur)
            blob += self.ministream[cur * self.mini_size:(cur + 1) * self.mini_size]
            if len(blob) >= size:
                break
            cur = self.mini_fat[cur] if cur < len(self.mini_fat) else _ENDOFCHAIN
        return bytes(blob[:size])


# --------------------------------------------------------------------------
# DestList stream (automatic destinations MRU)
# --------------------------------------------------------------------------

def parse_destlist_header(data):
    if len(data) < 32:
        raise JumpListParseError(f"DestList too small ({len(data)} bytes)")
    return {
        "version": _u32(data, 0),
        "entry_count": _u32(data, 4),
        "pinned_count": _u32(data, 8),
        "last_entry_id": _u32(data, 16),
        "revision": _u32(data, 24),
    }


# Sane DestList timestamp window: 2000-01-01 .. now+2d (FILETIME ticks).
# Used only to gate heuristic recovery walks, never to drop v1/v3/v4 rows.
_MIN_SANE_FT = int((dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)
                    - FILETIME_EPOCH).total_seconds() * 10_000_000)


def _sane_filetime(value):
    if not value:
        return False
    now_ft = int((dt.datetime.now(dt.timezone.utc)
                  + dt.timedelta(days=2) - FILETIME_EPOCH).total_seconds() * 10_000_000)
    return _MIN_SANE_FT <= value <= now_ft


def parse_destlist_entries_heuristic(data, stream_ids, notes):
    """Best-effort walks for unknown DestList versions.

    The core pre-path fields have been layout-stable since v1, so v1 and
    v3-shaped walks are attempted in turn -- but a row is kept ONLY if its
    entry ID matches a real numbered stream (the documented join invariant),
    its path decodes sanely, and its timestamp is sane-or-zero. The first
    layout yielding joined rows wins; anything else is skipped, never
    emitted. Every kept row is flagged heuristic=True so timelines stay
    auditable.
    """
    if not stream_ids:
        notes.append("heuristic DestList walk skipped (no numbered streams to join)")
        return []
    for layout, fixed, has_trailer in (("v1", 114, 0), ("v3", 130, 4)):
        rows = _heuristic_walk(data, stream_ids, notes, layout, fixed, has_trailer)
        if rows:
            notes.append(f"heuristic DestList walk matched {layout} layout "
                         f"({len(rows)} rows)")
            return rows
    notes.append("heuristic DestList walk matched no known layout; entries skipped")
    return []


def _heuristic_walk(data, stream_ids, notes, layout, fixed, has_trailer):
    entries = []
    off, index = 32, 0
    while off + fixed <= len(data):
        try:
            entry_id = _u32(data, off + 88)
            if entry_id not in stream_ids:
                if index == 0:
                    notes.append(f"heuristic ({layout}): first row joins no "
                                 f"stream; trying next layout")
                break
            raw_ft = _u64(data, off + 100)
            pin_raw = _u32(data, off + 108)
            if layout == "v1":
                access_count = _f32(data, off + 96)
                name_len = _u16(data, off + 112)
                name_off = off + 114
            else:
                access_count = _f32(data, off + 116)
                name_len = _u16(data, off + 128)
                name_off = off + 130
            if name_len == 0 or name_len > 32768 or \
                    name_off + name_len * 2 + has_trailer > len(data):
                notes.append(f"heuristic ({layout}) entry[{index}]: bad path "
                             f"length; trying next layout")
                break
            name = data[name_off:name_off + name_len * 2].decode("utf-16-le", "replace")
            if not name or not name.strip():
                notes.append(f"heuristic ({layout}) entry[{index}]: empty path; "
                             f"trying next layout")
                break
            moment = filetime_to_utc(raw_ft)
            if raw_ft and (moment is None or not _sane_filetime(raw_ft)):
                notes.append(f"heuristic ({layout}) entry[{index}]: implausible "
                             f"timestamp; trying next layout")
                break
            netbios = data[off + 72:off + 88].split(b"\x00")[0] \
                .decode("ascii", "replace").strip() or None
            entries.append({
                "index": index,
                "heuristic": True,
                "heuristic_layout": layout,
                "checksum": f"0x{_u64(data, off):016X}",
                "volume_guid": guid_mixed(data[off + 8:off + 24]),
                "object_guid": guid_mixed(data[off + 24:off + 40]),
                "birth_volume_guid": guid_mixed(data[off + 40:off + 56]),
                "birth_object_guid": guid_mixed(data[off + 56:off + 72]),
                "netbios_name": netbios,
                "entry_id": entry_id,
                "access_count": access_count,
                "last_access_time_utc": iso(moment),
                "pinned": pin_raw != 0xFFFFFFFF,
                "pin_order": None if pin_raw == 0xFFFFFFFF else pin_raw,
                "path": name,
            })
            off = name_off + name_len * 2 + has_trailer
            index += 1
        except JumpListParseError as exc:
            notes.append(f"heuristic ({layout}) entry[{index}] parse error: "
                         f"{exc}; trying next layout")
            break
        if index > 10000:
            notes.append("heuristic entry count capped at 10000; stopping")
            break
    return entries


def parse_destlist_entries(data, version, notes, stream_ids=None):
    """Parse DestList entries; returns list of dicts (v1 and v3/v4 layouts).

    Unknown versions fall back to a validated heuristic v1-layout walk (see
    parse_destlist_entries_heuristic): only rows whose entry ID matches a
    real stream are kept, so layout drift cannot inject garbage.
    """
    if version == 1:
        fixed, has_trailer = 114, 0
    elif version in (3, 4):
        fixed, has_trailer = 130, 4
    else:
        notes.append(f"unsupported DestList version {version}; "
                     f"trying validated heuristic walk")
        return parse_destlist_entries_heuristic(data, stream_ids or set(), notes)
    entries = []
    off = 32
    index = 0
    while off + 2 <= len(data):
        try:
            checksum = f"0x{_u64(data, off):016X}"
            volume_guid = guid_mixed(data[off + 8:off + 24])
            object_guid = guid_mixed(data[off + 24:off + 40])
            birth_volume_guid = guid_mixed(data[off + 40:off + 56])
            birth_object_guid = guid_mixed(data[off + 56:off + 72])
            netbios = data[off + 72:off + 88].split(b"\x00")[0] \
                .decode("ascii", "replace").strip() or None
            entry_id = _u32(data, off + 88)
            if version == 1:
                access_count = _f32(data, off + 96)
                last_access = iso(filetime_to_utc(_u64(data, off + 100)))
                pin_raw = _u32(data, off + 108)
                name_len = _u16(data, off + 112)
                name_off = off + 114
            else:
                counter_96 = _f32(data, off + 96)
                last_access = iso(filetime_to_utc(_u64(data, off + 100)))
                pin_raw = _u32(data, off + 108)
                field_112 = _u32(data, off + 112)
                access_count = _f32(data, off + 116)
                name_len = _u16(data, off + 128)
                name_off = off + 130
                if counter_96:
                    notes.append(f"entry[{index}]: nonzero v3 counter@96 ({counter_96})")
                if field_112:
                    notes.append(f"entry[{index}]: nonzero v3 field@112 ({field_112})")
            if name_len > 32768 or name_off + name_len * 2 + has_trailer > len(data):
                notes.append(f"entry[{index}]: path overruns DestList; stopping")
                break
            name = data[name_off:name_off + name_len * 2] \
                .decode("utf-16-le", "replace")
            entries.append({
                "index": index,
                "checksum": checksum,
                "volume_guid": volume_guid,
                "object_guid": object_guid,
                "birth_volume_guid": birth_volume_guid,
                "birth_object_guid": birth_object_guid,
                "netbios_name": netbios,
                "entry_id": entry_id,
                "access_count": access_count,
                "last_access_time_utc": last_access,
                "pinned": pin_raw != 0xFFFFFFFF,
                "pin_order": None if pin_raw == 0xFFFFFFFF else pin_raw,
                "path": name or None,
            })
            off = name_off + name_len * 2 + has_trailer
            index += 1
        except JumpListParseError as exc:
            notes.append(f"entry[{index}] parse error: {exc}; stopping")
            break
        if index > 10000:
            notes.append("entry count capped at 10000; stopping")
            break
    return entries


# --------------------------------------------------------------------------
# per-file parsers
# --------------------------------------------------------------------------

def _load_appid_map(path, notes):
    overrides = {}
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for sep in ("|", "#"):
                    if sep in line:
                        key, _, value = line.partition(sep)
                        key, value = key.strip().lower(), value.strip().strip("\"'")
                        if APPID_RE.match(key) and value:
                            overrides[key] = value
                        break
    except OSError as exc:
        notes.append(f"appid-map unreadable ({exc}); using built-in table")
    return overrides


def _file_times(path):
    stat = os.stat(path)
    modified = iso(dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc))
    created = (iso(dt.datetime.fromtimestamp(stat.st_birthtime, dt.timezone.utc))
               if hasattr(stat, "st_birthtime") else None)
    accessed = iso(dt.datetime.fromtimestamp(stat.st_atime, dt.timezone.utc))
    return modified, created, accessed


def _split_appid(basename):
    stem = basename[:-3] if basename.lower().endswith(".ms") else basename
    appid = stem.split(".")[0].lower()
    return appid if APPID_RE.match(appid) else None


def _common_netbios(entries):
    names = [e["netbios_name"] for e in entries if e.get("netbios_name")]
    if not names:
        return None
    ranked = sorted(set(names), key=lambda n: (-names.count(n), n))
    return ranked[0]


def _parse_stream_lnks(blob, stream_name, notes):
    """Parse LNK(s) from one automatic-destination stream blob.

    Flexible: an LNK at offset 0 is preferred; otherwise every embedded
    signature is carved (offset recorded alongside). Unparseable blobs are
    noted, never fatal. Returns [(lnk_record, carve_offset_or_None)].
    """
    found = []
    if len(blob) >= 0x4C and blob[:4] == b"L\x00\x00\x00" \
            and blob[4:20] == LNK_SIG[4:20]:
        try:
            return [(parse_lnk_bytes(blob), None)]
        except Exception as exc:  # noqa: BLE001 - fall through to carving
            notes.append(f"stream {stream_name} LNK@0 parse error "
                         f"({type(exc).__name__}: {exc}); trying carve")
    offsets = carve_lnk_offsets(blob)
    if not offsets:
        notes.append(f"stream {stream_name} holds no LNK signature (skipped)")
        return found
    for off in offsets:
        try:
            found.append((parse_lnk_bytes(blob[off:]), off))
        except Exception as exc:  # noqa: BLE001 - keep carving the rest
            notes.append(f"stream {stream_name} carved LNK@{off} parse error "
                         f"({type(exc).__name__}: {exc})")
    if len(offsets) > 1:
        notes.append(f"stream {stream_name}: {len(found)} LNK(s) carved from one stream")
    return found


def parse_automatic(path, machine_id=None, appid_table=None, strict_streams=True):
    """Parse one .automaticDestinations-ms file. Returns the record dict.

    strict_streams=False tolerates short (truncated) streams: partial bytes
    are still parsed instead of skipping the stream outright.
    """
    if appid_table is None:
        appid_table = KNOWN_APPIDS
    size = os.path.getsize(path)
    if size > MAX_SANE_FILE:
        raise JumpListParseError(f"file too large ({size} bytes)")
    if size < 512:
        raise JumpListParseError(f"file too small ({size} bytes)")
    with open(path, "rb") as fh:
        data = fh.read()

    notes = []
    base = os.path.basename(path)
    appid = _split_appid(base)
    if appid is None:
        notes.append(f"filename {base!r} carries no 16-hex AppID")
    app_name = (appid_table or {}).get(appid) if appid else None
    if appid and not app_name:
        notes.append(f"unknown AppID {appid} (app_name left empty)")

    ole = OleReader(data)
    streams = ole.streams()
    stream_ids = set()
    for name in streams:
        if name.lower() == "destlist":
            continue
        try:
            stream_ids.add(int(name, 16))
        except ValueError:
            pass  # non-hex names still get an LNK attempt below

    destlist = []
    destlist_header = None
    for name in streams:
        if name.lower() != "destlist":
            continue
        start, dsize = streams[name]
        try:
            raw = ole.read_stream(start, dsize, "DestList", strict=strict_streams)
            destlist_header = parse_destlist_header(raw)
            destlist = parse_destlist_entries(
                raw, destlist_header["version"], notes, stream_ids)
            if destlist_header["entry_count"] != len(destlist):
                notes.append(
                    f"DestList header claims {destlist_header['entry_count']} "
                    f"entries, parsed {len(destlist)}")
        except JumpListParseError as exc:
            notes.append(f"DestList unreadable ({exc}); LNK streams still parsed")
    if destlist_header is None:
        notes.append("no DestList stream; entry times come from embedded LNKs")

    by_entry_id = {}
    for e in destlist:
        by_entry_id.setdefault(e["entry_id"], e)
    # DestList array position doubles as the MRU rank (0 = most recent).
    mru_by_id = {dl["entry_id"]: i for i, dl in enumerate(destlist)}
    entries = []
    consumed_dl = set()
    for stream_name in sorted(streams, key=str):
        if stream_name.lower() == "destlist":
            continue
        start, ssize = streams[stream_name]
        try:
            blob = ole.read_stream(start, ssize, f"stream {stream_name}",
                                   strict=strict_streams)
        except JumpListParseError as exc:
            notes.append(f"stream {stream_name} unreadable ({exc})")
            continue
        try:
            stream_id = int(stream_name, 16)
        except ValueError:
            stream_id = None
            notes.append(f"stream {stream_name!r} has a non-hex name; "
                         f"parsed without DestList join")
        for lnk, carve_off in _parse_stream_lnks(blob, stream_name, notes):
            dl = None
            if stream_id is not None and stream_id not in consumed_dl:
                dl = by_entry_id.get(stream_id)
                if dl is not None:
                    consumed_dl.add(stream_id)
            elif stream_id is not None:
                notes.append(f"stream {stream_name}: extra carved LNK@{carve_off} "
                             f"kept without DestList row")
            target = lnk.get("target_path") or (dl or {}).get("path")
            entries.append({
                "entry_id": stream_id,
                "stream_name": stream_name,
                "carve_offset": carve_off,
                "mru_position": mru_by_id.get(stream_id),
                "target_path": target,
                "destlist": dl,
                "lnk": lnk,
            })

    # DestList rows whose stream is gone still name a file (deleted/moved).
    matched = {e["entry_id"] for e in entries if e["entry_id"] is not None}
    for dl in destlist:
        if dl["entry_id"] not in matched:
            notes.append(
                f"DestList entry id {dl['entry_id']} ({dl['path']}) has no LNK stream")
            entries.append({
                "entry_id": dl["entry_id"],
                "stream_name": None,
                "mru_position": mru_by_id.get(dl["entry_id"]),
                "target_path": dl["path"],
                "destlist": dl,
                "lnk": None,
            })

    modified, created, accessed = _file_times(path)
    return _build_record(
        path=path, size=size, destinations_type="automatic", appid=appid,
        app_name=app_name, destlist_header=destlist_header, entries=entries,
        machine_id=machine_id, parsers_used=["builtin", "ole-cfb"],
        notes=notes, modified=modified, created=created, accessed=accessed)


def carve_lnk_offsets(data):
    """Offsets of every full LNK-signature occurrence (sig + LinkCLSID)."""
    offsets = []
    pos = 0
    while True:
        hit = data.find(LNK_SIG, pos)
        if hit == -1:
            return offsets
        offsets.append(hit)
        pos = hit + 4


def parse_custom(path, machine_id=None, appid_table=None):
    """Parse one .customDestinations-ms file (carved LNK concatenation)."""
    if appid_table is None:
        appid_table = KNOWN_APPIDS
    size = os.path.getsize(path)
    if size > MAX_SANE_FILE:
        raise JumpListParseError(f"file too large ({size} bytes)")
    if size < 0x4C + 4:
        raise JumpListParseError(f"file too small ({size} bytes)")
    with open(path, "rb") as fh:
        data = fh.read()

    notes = []
    base = os.path.basename(path)
    appid = _split_appid(base)
    if appid is None:
        notes.append(f"filename {base!r} carries no 16-hex AppID")
    app_name = (appid_table or {}).get(appid) if appid else None
    if appid and not app_name:
        notes.append(f"unknown AppID {appid} (app_name left empty)")
    notes.append("custom destinations carry no container timestamps; "
                 "event times fall back to embedded LNK target times")

    offsets = carve_lnk_offsets(data)
    if not offsets:
        raise JumpListParseError("no embedded LNK signatures found")
    entries = []
    for index, start in enumerate(offsets):
        end = offsets[index + 1] if index + 1 < len(offsets) else len(data)
        blob = data[start:end]
        if len(blob) < 0x4C:
            notes.append(f"carved LNK #{index} truncated ({len(blob)} bytes)")
            continue
        try:
            lnk = parse_lnk_bytes(blob)
        except Exception as exc:  # noqa: BLE001 - keep carving the rest
            notes.append(f"carved LNK #{index} parse error "
                         f"({type(exc).__name__}: {exc})")
            continue
        entries.append({
            "entry_id": None,
            "stream_name": None,
            "carve_index": index,
            "carve_offset": start,
            "target_path": lnk.get("target_path"),
            "destlist": None,
            "lnk": lnk,
        })
    if not entries:
        raise JumpListParseError("no parseable embedded LNK found")

    modified, created, accessed = _file_times(path)
    return _build_record(
        path=path, size=size, destinations_type="custom", appid=appid,
        app_name=app_name, destlist_header=None, entries=entries,
        machine_id=machine_id, parsers_used=["builtin", "lnk-carve"],
        notes=notes, modified=modified, created=created, accessed=accessed)


def _build_record(path, size, destinations_type, appid, app_name,
                   destlist_header, entries, machine_id, parsers_used,
                   notes, modified, created, accessed=None):
    flat = []
    for item in entries:
        dl = item["destlist"] or {}
        lnk = item["lnk"] or {}
        stamp, source = None, None
        if dl.get("last_access_time_utc"):
            stamp, source = dl["last_access_time_utc"], "destlist_last_access"
        else:
            for field, label in (
                ("target_modification_time_utc", "lnk_target_modification"),
                ("target_access_time_utc", "lnk_target_access"),
                ("target_creation_time_utc", "lnk_target_creation"),
            ):
                if lnk.get(field):
                    stamp, source = lnk[field], label
                    break
        flat.append({
            "entry_id": item["entry_id"],
            "stream_name": item["stream_name"],
            "carve_index": item.get("carve_index"),
            "carve_offset": item.get("carve_offset"),
            "mru_position": item.get("mru_position"),
            "target_path": item["target_path"],
            "timestamp_utc": stamp,
            "timestamp_source": source,
            "access_count": dl.get("access_count"),
            "pinned": dl.get("pinned"),
            "pin_order": dl.get("pin_order"),
            "checksum": dl.get("checksum"),
            "netbios_name": dl.get("netbios_name"),
            "volume_guid": dl.get("volume_guid"),
            "object_guid": dl.get("object_guid"),
            "destlist_path": dl.get("path"),
            "lnk_target_creation_time_utc": lnk.get("target_creation_time_utc"),
            "lnk_target_access_time_utc": lnk.get("target_access_time_utc"),
            "lnk_target_modification_time_utc": lnk.get("target_modification_time_utc"),
            "lnk_target_source": lnk.get("target_source"),
            "lnk_target_file_size": lnk.get("target_file_size"),
            "lnk_arguments": lnk.get("arguments"),
            "lnk_working_directory": lnk.get("working_directory"),
            "lnk_volume_serial_number": lnk.get("volume_serial_number"),
            "lnk_machine_id": lnk.get("machine_id"),
            "destlist_heuristic": bool(dl.get("heuristic")),
        })
    if machine_id is None:
        machine_id = _common_netbios([e for e in flat])
        if machine_id is None:
            lnk_hosts = [e["lnk_machine_id"] for e in flat if e.get("lnk_machine_id")]
            if lnk_hosts:
                machine_id = sorted(set(lnk_hosts),
                                    key=lambda n: (-lnk_hosts.count(n), n))[0]
                notes.append(
                    f"machine_id {machine_id} inferred from embedded LNK "
                    f"TrackerData ({lnk_hosts.count(machine_id)}/"
                    f"{len(lnk_hosts)} entries carrying a host)")
    return {
        "jumplists_file": os.path.basename(path),
        "jumplists_path": os.path.abspath(path),
        "jumplists_file_size": size,
        "destinations_type": destinations_type,
        "appid": appid,
        "app_name": app_name,
        "destlist_version": (destlist_header or {}).get("version"),
        "destlist_entry_count": (destlist_header or {}).get("entry_count"),
        "destlist_pinned_count": (destlist_header or {}).get("pinned_count"),
        "entries": flat,
        "machine_id": machine_id,
        "parsers_used": parsers_used,
        "notes": notes,
        "jl_file_modified_utc": modified,
        "jl_file_created_utc": created,
        "jl_file_accessed_utc": accessed,
    }


def parse_jumplist_file(path, machine_id=None, appid_table=None, strict_streams=True):
    """Dispatch on filename suffix, sniffing content when it is unknown.

    Raises JumpListParseError on failure.
    """
    lower = os.path.basename(path).lower()
    if lower.endswith(AUTO_SUFFIX):
        return parse_automatic(path, machine_id=machine_id, appid_table=appid_table,
                               strict_streams=strict_streams)
    if lower.endswith(CUSTOM_SUFFIX):
        return parse_custom(path, machine_id=machine_id, appid_table=appid_table)
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if head[:8] == OLE_MAGIC:
        record = parse_automatic(path, machine_id=machine_id, appid_table=appid_table,
                                 strict_streams=strict_streams)
        record["notes"].insert(
            0, f"unrecognized suffix {os.path.basename(path)!r}; "
               f"sniffed as automaticDestinations (OLE)")
        return record
    if LNK_SIG in head:
        record = parse_custom(path, machine_id=machine_id, appid_table=appid_table)
        record["notes"].insert(
            0, f"unrecognized suffix {os.path.basename(path)!r}; "
               f"sniffed as customDestinations (LNK content)")
        return record
    raise JumpListParseError(f"unsupported suffix (want *{AUTO_SUFFIX} / *{CUSTOM_SUFFIX})")


# --------------------------------------------------------------------------
# timeline construction (same event schema as the LNK / Prefetch engines)
# --------------------------------------------------------------------------

def _base_event(record, timestamp, timestamp_type, target_path, entry):
    return {
        "timestamp": timestamp,
        "timestamp_type": timestamp_type,
        "source": "JumpLists",
        "artifact_type": "jumplists",
        "jumplists_file": record["jumplists_file"],
        "jumplists_path": record["jumplists_path"],
        "jumplists_name": record["jumplists_file"],
        "artifact_name": record["jumplists_file"],
        "appid": record["appid"],
        "app_name": record["app_name"],
        "target_path": target_path,
        "details": {
            "appid": record["appid"],
            "app_name": record["app_name"],
            "destinations_type": record["destinations_type"],
            "entry_id": entry.get("entry_id"),
            "stream_name": entry.get("stream_name"),
            "carve_index": entry.get("carve_index"),
            "mru_position": entry.get("mru_position"),
            "checksum": entry.get("checksum"),
            "netbios_name": entry.get("netbios_name"),
            "access_count": entry.get("access_count"),
            "pinned": entry.get("pinned"),
            "pin_order": entry.get("pin_order"),
            "timestamp_source": entry.get("timestamp_source"),
            "lnk_target_creation_time_utc": entry.get("lnk_target_creation_time_utc"),
            "lnk_target_access_time_utc": entry.get("lnk_target_access_time_utc"),
            "lnk_target_modification_time_utc": entry.get(
                "lnk_target_modification_time_utc"),
            "lnk_target_source": entry.get("lnk_target_source"),
            "lnk_target_file_size": entry.get("lnk_target_file_size"),
            "lnk_arguments": entry.get("lnk_arguments"),
            "lnk_working_directory": entry.get("lnk_working_directory"),
            "lnk_volume_serial_number": entry.get("lnk_volume_serial_number"),
            "lnk_machine_id": entry.get("lnk_machine_id"),
            "destlist_heuristic": entry.get("destlist_heuristic", False),
            "machine_id": record["machine_id"],
            "parsers_used": record["parsers_used"],
        },
    }


def make_events(record):
    events = []
    for entry in record.get("entries", []):
        if not entry.get("timestamp_utc") or not entry.get("target_path"):
            continue
        label = ("Jump List Accessed"
                 if record["destinations_type"] == "automatic" else "Jump List Entry")
        events.append(_base_event(
            record, entry["timestamp_utc"], label, entry["target_path"], entry))
    for label, field, source in (
        ("JumpList File Modified", "jl_file_modified_utc", "file_mtime"),
        ("JumpList File Created", "jl_file_created_utc", "file_birthtime"),
    ):
        stamp = record.get(field)
        if not stamp:
            continue
        file_entry = {"timestamp_source": source}
        events.append(_base_event(
            record, stamp, label, record["jumplists_file"], file_entry))
    return events


# --------------------------------------------------------------------------
# file discovery and CLI
# --------------------------------------------------------------------------

def iter_jumplist_files(root, recursive, accept_all=False):
    wanted = (AUTO_SUFFIX, CUSTOM_SUFFIX)
    if recursive:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames):
                lower = name.lower()
                if lower.endswith(wanted) or (accept_all and lower.endswith(".ms")):
                    yield os.path.join(dirpath, name)
    else:
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            lower = name.lower()
            if os.path.isfile(full) and \
                    (lower.endswith(wanted) or (accept_all and lower.endswith(".ms"))):
                yield full


def truncate(text, width):
    if text is None or text == "":
        return "-"
    text = str(text)
    return text if len(text) <= width else text[:width - 3] + "..."


def _plain_table(rows, headers):
    widths = [max(len(str(headers[i])), *(len(str(r[i])) for r in rows))
              for i in range(len(headers))]
    line = "  ".join(str(headers[i]).ljust(widths[i]) for i in range(len(headers)))
    sep = "  ".join("-" * widths[i] for i in range(len(headers)))
    body = ["  ".join(str(r[i]).ljust(widths[i]) for i in range(len(headers))) for r in rows]
    return "\n".join([line, sep] + body)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog=TOOL,
        description="Parse Windows Jump Lists into a chronological JSON "
                    "timeline (same schema as lnk_forensics.py).")
    parser.add_argument("path", nargs="?", default=".",
                        help="directory with Jump List files or a single "
                             "*.automaticDestinations-ms / *.customDestinations-ms file")
    parser.add_argument("-o", "--output", default="jumplists_timeline.json",
                        help="output JSON file (default: jumplists_timeline.json)")
    parser.add_argument("--flat", action="store_true",
                        help="do not recurse into subdirectories (default: recursive)")
    parser.add_argument("--all", action="store_true",
                        help="also try files with other *.ms suffixes")
    parser.add_argument("--machine-id", default=None,
                        help="host identifier stamped into details.machine_id "
                             "(defaults to the DestList NetBIOS name)")
    parser.add_argument("--appid-map", default=None,
                        help="extra AppID map file (lines like: appid|description)")
    parser.add_argument("--strict", action="store_true",
                        help="fail-fast stream reads: skip (instead of partially "
                             "parsing) truncated OLE streams (default: flexible)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress the console summary table")
    args = parser.parse_args(argv)

    table = dict(KNOWN_APPIDS)
    map_notes = []
    if args.appid_map:
        table.update(_load_appid_map(os.path.abspath(args.appid_map), map_notes))

    target = os.path.abspath(args.path)
    if os.path.isfile(target):
        candidates = [target]
        scan_root, recursive = os.path.dirname(target) or ".", False
    elif os.path.isdir(target):
        scan_root, recursive = target, not args.flat
        candidates = list(iter_jumplist_files(target, recursive=recursive,
                                              accept_all=args.all))
    else:
        print(f"[!] no such file or directory: {target}", file=sys.stderr)
        return 2

    engine = ["builtin", "ole-cfb", "lnk-carve"]
    records, skipped, events = [], [], []
    for path in candidates:
        try:
            record = parse_jumplist_file(path, machine_id=args.machine_id,
                                         appid_table=table,
                                         strict_streams=args.strict)
            record["notes"] = map_notes + record["notes"]
        except Exception as exc:  # noqa: BLE001 - per-file resilience, mirrors LNK
            skipped.append({"file": os.path.abspath(path),
                            "error_type": type(exc).__name__,
                            "error": str(exc)})
            print(f"[!] skipped {path} ({type(exc).__name__}: {exc})", file=sys.stderr)
            continue
        records.append(record)
        events.extend(make_events(record))

    events.sort(key=lambda e: (e["timestamp"], e["jumplists_path"],
                               e["timestamp_type"]))

    machines = sorted({r["machine_id"] for r in records if r["machine_id"]})
    apps = sorted({r["app_name"] or r["appid"] or "?" for r in records})
    document = {
        "metadata": {
            "tool": TOOL,
            "version": VERSION,
            "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "target_directory": scan_root,
            "scan_mode": "flat" if args.flat else "recursive",
            "parser_engine": engine,
            "timestamps_format": "ISO 8601 UTC",
            "machine_id": args.machine_id,
            "counts": {
                "jl_files_found": len(records) + len(skipped),
                "jl_files_parsed": len(records),
                "jl_files_failed": len(skipped),
                "timeline_events": len(events),
                "unique_apps": apps,
                "unique_targets": len({e["target_path"] for r in records
                                       for e in r["entries"] if e["target_path"]}),
                "types_observed": sorted({r["destinations_type"] for r in records}),
                "machines_observed": machines,
            },
        },
        "events": events,
        "artifacts": records,
        "skipped": skipped,
    }

    out_path = os.path.abspath(args.output)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    if not args.quiet:
        rows = [[i + 1, truncate(r["jumplists_file"], 34),
                 truncate(r["app_name"] or r["appid"], 26),
                 r["destinations_type"], len(r["entries"]),
                 truncate((next((e["timestamp_utc"] for e in r["entries"]
                                 if e["timestamp_utc"]), None)), 26)]
                for i, r in enumerate(records)]
        print(f"\n[{TOOL}] {target} -> {out_path}")
        print(_plain_table(
            rows, ["#", "JumpList File", "Application", "Type", "Entries",
                   "Latest Entry (UTC)"]) if rows else "(no parsed artifacts)")
        print()
        print(f"[+] {len(records)} Jump Lists parsed, {len(skipped)} skipped, "
              f"{len(events)} timeline events -> {out_path}")
        if machines:
            print("[+] machines observed: " + ", ".join(machines))
        if skipped:
            print(f"[!] {len(skipped)} file(s) could not be parsed (see 'skipped' in JSON)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
