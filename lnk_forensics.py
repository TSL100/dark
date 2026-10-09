#!/usr/bin/env python3
"""
lnk_forensics.py - Windows LNK (.lnk) parser -> chronological JSON timeline.

DFIR PoC engine for a forensic GUI tool. Parses Windows shortcut files per
[MS-SHLLINK] and extracts target paths (with multi-source recovery), target
timestamps (creation/access/modification from the ShellLinkHeader), volume
serial numbers (LinkInfo/VolumeID), machine identifiers (TrackerDataBlock),
DROID GUIDs, and builds a chronological timeline of events.

Parsers:
  - builtin: pure-Python, spec-compliant, dependency-free (default engine)
  - pylnk3:  optional enrichment (library import guarded)

Usage:
    python lnk_forensics.py [DIRECTORY] [-o OUTPUT.json] [--flat]
                            [--no-pylnk3] [--no-tabulate] [-q]

Examples:
    python lnk_forensics.py samples
    python lnk_forensics.py "C:\\Users\\x\\Desktop" -o desktop_lnk.json
    python lnk_forensics.py samples --flat --no-tabulate
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import struct
import sys
import uuid

try:
    import pylnk3
except Exception:  # noqa: BLE001 (optional dependency / untrusted input guard)
    pylnk3 = None

try:
    from tabulate import tabulate
except Exception:  # noqa: BLE001 (optional dependency / untrusted input guard)
    tabulate = None

TOOL = "lnk_forensics.py"
VERSION = "1.1.0"

FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
MAX_SANE_FILE = 64 * 1024 * 1024
LNK_SIGNATURE = b"L\x00\x00\x00"
LNK_CLSID = bytes.fromhex("0114020000000000C000000000000046")

HAS_LINK_TARGET_IDLIST = 0x00000001
HAS_LINK_INFO = 0x00000002
HAS_NAME = 0x00000004
HAS_RELATIVE_PATH = 0x00000008
HAS_WORKING_DIR = 0x00000010
HAS_ARGUMENTS = 0x00000020
HAS_ICON_LOCATION = 0x00000040
IS_UNICODE = 0x00000080

LINK_FLAGS = (
    "HasLinkTargetIDList", "HasLinkInfo", "HasName", "HasRelativePath",
    "HasWorkingDir", "HasArguments", "HasIconLocation", "IsUnicode",
    "ForceNoLinkInfo", "HasExpString", "RunInSeparateProcess", "Unused1",
    "HasDarwinID", "RunAsUser", "HasExpIcon", "NoPidlAlias", "Unused2",
    "RunWithShimLayer", "ForceNoLinkTrack", "EnableTargetMetadata",
    "DisableLinkPathTracking", "DisableKnownFolderTracking",
    "DisableKnownFolderAlias", "AllowLinkToLink", "UnaliasOnSave",
    "PreferEnvironmentPath", "KeepLocalIDListForUNCTarget",
)

FILE_ATTRIBUTE_FLAGS = (
    "read_only", "hidden", "system_file", "reserved1", "directory",
    "archive", "reserved2", "normal", "temporary", "sparse_file",
    "reparse_point", "compressed", "offline", "not_content_indexed",
    "encrypted",
)

DRIVE_TYPES = {
    0: "Unknown", 1: "No root directory", 2: "Removable",
    3: "Fixed (Hard disk)", 4: "Remote (Network drive)", 5: "CD-ROM",
    6: "RAM disk",
}

SHOW_COMMANDS = {
    0: "SW_HIDE", 1: "SW_SHOWNORMAL", 2: "SW_SHOWMINIMIZED",
    3: "SW_SHOWMAXIMIZED", 4: "SW_SHOWNOACTIVATE", 5: "SW_SHOW",
    6: "SW_MINIMIZE", 7: "SW_SHOWMINNOACTIVE", 8: "SW_SHOWNA",
    9: "SW_RESTORE", 10: "SW_SHOWDEFAULT",
}

# CSIDL values for SpecialFolderDataBlock (curated common set).
CSIDL_NAMES = {
    0x00: "DESKTOP", 0x01: "INTERNET", 0x02: "PROGRAMS", 0x03: "CONTROLS",
    0x04: "PRINTERS", 0x05: "PERSONAL", 0x06: "FAVORITES", 0x07: "STARTUP",
    0x08: "RECENT", 0x09: "SENDTO", 0x0A: "BITBUCKET", 0x0B: "STARTMENU",
    0x0D: "MYMUSIC", 0x0E: "MYVIDEO", 0x10: "DESKTOPDIRECTORY",
    0x13: "NETHOOD", 0x14: "FONTS", 0x15: "TEMPLATES",
    0x16: "COMMON_STARTMENU", 0x17: "COMMON_PROGRAMS",
    0x18: "COMMON_STARTUP", 0x19: "COMMON_DESKTOPDIRECTORY",
    0x1A: "APPDATA", 0x1B: "PRINTHOOD", 0x1C: "LOCAL_APPDATA",
    0x1D: "ALTSTARTUP", 0x1E: "COMMON_ALTSTARTUP",
    0x1F: "COMMON_FAVORITES", 0x20: "INTERNET_CACHE", 0x21: "COOKIES",
    0x22: "HISTORY", 0x23: "COMMON_APPDATA", 0x24: "WINDOWS",
    0x25: "SYSTEM", 0x26: "PROGRAM_FILES", 0x27: "MYPICTURES",
    0x28: "PROFILE", 0x29: "SYSTEMX86", 0x2A: "PROGRAM_FILESX86",
    0x2D: "COMMON_TEMPLATES", 0x2E: "COMMON_DOCUMENTS",
    0x2F: "COMMON_ADMINTOOLS", 0x30: "ADMINTOOLS", 0x31: "CONNECTIONS",
    0x35: "COMMON_MUSIC", 0x36: "COMMON_PICTURES", 0x37: "COMMON_VIDEO",
    0x38: "RESOURCES", 0x3B: "CDBURN_AREA", 0x3D: "COMPUTERSNEARME",
}

# DCE UUID epoch for v1 DROID GUID timestamps (100ns ticks).
UUID_EPOCH = dt.datetime(1582, 10, 15, tzinfo=dt.timezone.utc)

ROOT_FOLDER_GUIDS = {
    "20D04FE0-3AEA-1069-A2D8-08002B30309D": "MY_COMPUTER",
    "450D8FBA-AD25-11D0-98A8-0800361B1103": "MY_DOCUMENTS",
    "54A754C0-4BF1-11D1-83EE-00A0C90DC849": "NETWORK_SHARE",
    "C0542A90-4BF0-11D1-83EE-00A0C90DC849": "NETWORK_SERVER",
    "208D2C60-3AEA-1069-A2D7-08002B30309D": "NETWORK_PLACES",
    "46E06680-4BF0-11D1-83EE-00A0C90DC849": "NETWORK_DOMAIN",
    "871C5380-42A0-1069-A2EA-08002B30309D": "INTERNET",
    "645FF040-5081-101B-9F08-00AA002F954E": "RECYCLE_BIN",
    "21EC2020-3AEA-1069-A2DD-08002B30309D": "CONTROL_PANEL",
    "59031A47-3F72-44A7-89C5-5595FE6B30EE": "USERPROFILE",
    "4234D49B-0245-4DF3-B780-3893943456E1": "UWP_APPS",
    "B4BFCC3A-DB2C-424C-B029-7FE99A87C641": "USERS",
}

EXTRA_SIGNATURES = {
    0xA0000001: "EnvironmentVariableDataBlock",
    0xA0000002: "ConsoleDataBlock",
    0xA0000003: "TrackerDataBlock",
    0xA0000004: "ConsoleFEDataBlock",
    0xA0000005: "SpecialFolderDataBlock",
    0xA0000006: "DarwinDataBlock",
    0xA0000007: "IconEnvironmentDataBlock",
    0xA0000008: "ShimDataBlock",
    0xA0000009: "PropertyStoreDataBlock",
    0xA000000B: "KnownFolderDataBlock",
    0xA000000C: "VistaAndAboveIDListDataBlock",
}

PROPERTY_STORE_STRINGS_FORMAT = uuid.UUID("D5CDD505-2E9C-101B-9397-08002B2CF9AE").bytes_le
TARGET_PROPERTY_NAMES = (
    "System.Link.TargetParsingPath",
    "System.ItemPathDisplay",
    "System.Link.TargetExtension",
    "System.ItemType",
    "System.Title",
    "System.Subject",
    "System.Comment",
)


# --------------------------------------------------------------------------
# small binary helpers
# --------------------------------------------------------------------------

def _u16(data, off):
    if off + 2 > len(data):
        raise ValueError("unexpected end of data")
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    if off + 4 > len(data):
        raise ValueError("unexpected end of data")
    return struct.unpack_from("<I", data, off)[0]


def _u64(data, off):
    if off + 8 > len(data):
        raise ValueError("unexpected end of data")
    return struct.unpack_from("<Q", data, off)[0]


def filetime_to_utc(value):
    """FILETIME (100ns since 1601-01-01 UTC) -> aware UTC datetime, or None."""
    if not value:
        return None
    try:
        return FILETIME_EPOCH + dt.timedelta(microseconds=value // 10)
    except (OverflowError, OSError, ValueError):
        return None


def iso(dtobj):
    return dtobj.astimezone(dt.timezone.utc).isoformat() if dtobj else None


def read_ansi(data, off):
    end = data.find(b"\x00", off)
    if end == -1:
        end = len(data)
    return data[off:end].decode("cp1252", "replace")


def read_cunicode(data, off):
    end = off
    while end + 2 <= len(data) and data[end:end + 2] != b"\x00\x00":
        end += 2
    return data[off:end].decode("utf-16-le", "replace")


def guid_str(raw):
    try:
        return f"{{{str(uuid.UUID(bytes_le=raw)).upper()}}}"
    except (ValueError, TypeError):
        return None


def decode_hotkey(raw):
    """LNK hotkey word -> 'Ctrl+Alt+A' style string, or None if unset."""
    if not raw:
        return None
    key, mods = raw & 0xFF, (raw >> 8) & 0xFF
    parts = [name for bit, name in ((0x01, "Shift"), (0x02, "Ctrl"), (0x04, "Alt"))
             if mods & bit]
    if 0x20 <= key <= 0x7E:
        parts.append(chr(key).upper())
    else:
        parts.append(f"0x{key:02X}")
    return "+".join(parts)


def droid_guid_info(raw):
    """16-byte mixed-endian DROID GUID -> (version, mac, creation_utc).

    Mirrors Eric Zimmerman's Lnk library: DCE v1 UUIDs embed the host MAC
    (node field) and a creation timestamp. Non-v1 GUIDs yield (version,
    None, None) -- a MAC is never fabricated from random GUID bytes.
    """
    if len(raw) != 16:
        return None, None, None
    time_low, time_mid, time_hi = struct.unpack_from("<IHH", raw, 0)
    version = (time_hi >> 12) & 0xF
    if version != 1:
        return version, None, None
    # v1 layout: time_low (bits 0-31), time_mid (32-47), time_hi low 12 (48-59).
    ticks = time_low | (time_mid << 32) | ((time_hi & 0x0FFF) << 48)
    try:
        created = UUID_EPOCH + dt.timedelta(microseconds=ticks // 10)
    except (OverflowError, OSError, ValueError):
        created = None
    mac = ":".join(f"{b:02X}" for b in raw[10:16])
    return version, mac, iso(created)


def clean_drive_path(path):
    if not path:
        return None
    for root in ROOT_FOLDER_GUIDS.values():
        prefix = f"%%{root}%%\\"
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    return path.strip()


# --------------------------------------------------------------------------
# shell item (IDList) structures
# --------------------------------------------------------------------------

def _parse_path_segment(data):
    """Parse one file/folder shell item; returns display name or None."""
    try:
        if len(data) < 14:
            return None
        type_byte = data[0]
        if type_byte not in (0x31, 0x32, 0x35, 0x36):
            return None
        item_type = _u16(data, 0)
        is_unicode = item_type in (0x35, 0x36)
        p = 12  # type(2) file_size(4) dos_modified(4) attributes(2)
        if is_unicode:
            short_name = read_cunicode(data, p)
            p += len(short_name.encode("utf-16-le")) + 2
        else:
            short_name = read_ansi(data, p)
            p += len(short_name.encode("cp1252", "replace")) + 1
            if p % 2:
                p += 1
        # extension block: size(2) version(2) signature(4)
        extra_size = _u16(data, p)
        extra_version = _u16(data, p + 2)
        extra_sig = _u32(data, p + 4)
        full_name = None
        if extra_sig == 0xBEEF0004 and extra_size >= 14:
            q = p + 18  # header(8) + created(4) + accessed(4) + offset_unicode(2)
            if extra_version >= 7:
                q += 18  # offset_ansi(2) + file_reference(8) + unknown(8)
            if extra_version >= 3:
                q += 2  # long_string_size
            if extra_version >= 9:
                q += 4
            if extra_version >= 8:
                q += 4
            if extra_version >= 3:
                full_name = read_cunicode(data, q)
        return full_name or short_name or None
    except (ValueError, IndexError):
        return None


def _extract_uri(data):
    raw = bytes(data)
    for scheme in (b"http://", b"https://", b"ftp://"):
        pos = raw.find(scheme)
        if pos != -1:
            end = raw.find(b"\x00", pos)
            return raw[pos:end if end != -1 else len(raw)].decode("cp1252", "replace")
    return None


def parse_idlist(data, start, idlist_bytes):
    """Walk a shell ItemID list; return (path, notes)."""
    notes = []
    segments = []
    drive = None
    p = 0
    while p + 2 <= len(idlist_bytes):
        size = _u16(idlist_bytes, p)
        if size <= 0:
            break
        if p + size > len(idlist_bytes):
            notes.append(f"malformed shell item at offset {start + p}")
            break
        item = idlist_bytes[p + 2:p + size]
        p += size
        if not item:
            continue
        first = item[0]
        if first == 0x1F:  # root folder
            if len(item) >= 18:
                guid = guid_str(item[2:18])
                root_name = ROOT_FOLDER_GUIDS.get(guid.strip("{}").upper(), guid)
                notes.append(f"root folder: {root_name}")
            continue
        if first == 0x2F:  # drive
            if len(item) >= 3:
                drive = item[1:3].decode("cp1252", "replace")
            continue
        if item[0:2] == b"\x2E\x80":  # root known folder
            if len(item) >= 18:
                segments.append("::" + (guid_str(item[2:18]) or ""))
            continue
        if len(item) >= 4 and item[4:8] == b"APPS":
            notes.append("UWP/Store application link in IDList")
            return None, notes
        if first == 0x61:
            uri = _extract_uri(item)
            if uri:
                return uri, notes
            continue
        if first in (0x71, 0x76):  # control panel / delegate items
            continue
        name = _parse_path_segment(item)
        if name:
            segments.append(name)
    if not segments and not drive:
        return None, notes
    path = "\\".join(segments)
    if drive:
        path = (drive + "\\" + path) if segments else drive
    return path, notes


# --------------------------------------------------------------------------
# builtin parser (MS-SHLLINK)
# --------------------------------------------------------------------------

def _parse_link_info(data, li_start, record):
    if li_start + 28 > len(data):
        raise ValueError("LinkInfo truncated")
    li_size = _u32(data, li_start)
    li_hdr_size = _u32(data, li_start + 4)
    li_flags = _u32(data, li_start + 8)
    if li_size < 0x1C or li_start + li_size > len(data):
        raise ValueError(f"invalid LinkInfo size {li_size}")
    unicode_form = li_hdr_size >= 0x24

    if li_flags & 0x01:  # VolumeIDAndLocalBasePath
        vol_off = _u32(data, li_start + 12)
        base_off = _u32(data, li_start + 16)
        suffix_off = _u32(data, li_start + 24)
        base_off_u = _u32(data, li_start + 36) if unicode_form else 0
        suffix_off_u = _u32(data, li_start + 40) if unicode_form else 0

        v = li_start + vol_off
        if v + 16 <= len(data):
            record["drive_type"] = DRIVE_TYPES.get(_u32(data, v + 4))
            record["volume_serial_number"] = f"0x{_u32(data, v + 8):08X}"
            label_off = _u32(data, v + 12)
            if unicode_form and label_off == 0x14 and v + 20 <= len(data):
                label_off_u = _u32(data, v + 16)
                record["volume_label"] = read_cunicode(data, v + label_off_u).strip("\x00") or None
            elif label_off:
                record["volume_label"] = read_ansi(data, v + label_off).strip("\x00") or None

        base, suffix = None, None
        if base_off:
            base = read_ansi(data, li_start + base_off)
        if suffix_off:
            suffix = read_ansi(data, li_start + suffix_off)
        if base_off_u:
            base = read_cunicode(data, li_start + base_off_u)
        if suffix_off_u:
            suffix = read_cunicode(data, li_start + suffix_off_u)
        if base is not None:
            record["target_path"] = (base + (suffix or "")).strip("\x00") or None
            if record["target_path"]:
                record["target_source"] = "link_info"
            record["local_base_path"] = base.strip("\x00") or None
            record["common_path_suffix"] = (suffix or "").strip("\x00") or None

    elif li_flags & 0x02:  # CommonNetworkRelativeLink
        cnrl_off = _u32(data, li_start + 20)
        suffix_off = _u32(data, li_start + 24)
        c = li_start + cnrl_off
        if c + 20 > len(data):
            record["notes"].append("CommonNetworkRelativeLink truncated")
        else:
            net_name_off = _u32(data, c + 8)
            net_name_off_u = _u32(data, c + 20) if net_name_off > 0x14 else 0
            share = None
            if net_name_off_u:
                share = read_cunicode(data, c + net_name_off_u)
            elif net_name_off:
                share = read_ansi(data, c + net_name_off)
            record["net_name"] = (share or "").strip("\x00") or None
            if c + 28 <= len(data):
                record["network_provider_type"] = f"0x{_u32(data, c + 16):08X}"
                dev_off = _u32(data, c + 12)
                dev_off_u = _u32(data, c + 24) if dev_off and dev_off > 0x14 else 0
                device = None
                if dev_off_u:
                    device = read_cunicode(data, c + dev_off_u)
                elif dev_off:
                    device = read_ansi(data, c + dev_off)
                record["device_name"] = (device or "").strip("\x00") or None
            suffix = read_ansi(data, li_start + suffix_off) if suffix_off else ""
            record["common_path_suffix"] = suffix.strip("\x00") or None
            if share:
                record["target_path"] = (share.rstrip("\\") + "\\" + (suffix or "").lstrip("\\")).strip("\x00")
                record["target_source"] = "link_info_network"


def _parse_extra_data(data, start, record):
    notes = record["notes"]
    off = start
    blocks = set(record["extra_data_blocks"])
    while off + 4 <= len(data):
        size = _u32(data, off)
        if size < 4:
            break  # TerminalBlock
        if off + size > len(data):
            notes.append(f"ExtraData block at 0x{off:X} overruns EOF")
            break
        sig = _u32(data, off + 4) if size >= 8 else None
        payload = data[off + 8:off + size]
        name = EXTRA_SIGNATURES.get(sig, f"Unknown_0x{sig:08X}" if sig else "Terminal")
        blocks.add(name)
        try:
            if sig == 0xA0000003 and len(payload) >= 88:
                record["tracker_version"] = struct.unpack_from("<i", payload, 0)[0]
                machine = payload[8:24].split(b"\x00")[0].decode("cp1252", "replace").strip()
                record["machine_id"] = machine or None
                record["droid_volume_guid"] = guid_str(payload[24:40])
                record["droid_file_guid"] = guid_str(payload[40:56])
                record["droid_birth_volume_guid"] = guid_str(payload[56:72])
                record["droid_birth_file_guid"] = guid_str(payload[72:88])
                version, mac, created = droid_guid_info(bytes(payload[40:56]))
                record["droid_guid_version"] = version
                if version == 1:
                    record["mac_address"] = mac
                    record["droid_creation_time_utc"] = created
                elif version is not None:
                    notes.append("non-v1 file-droid GUID; MAC/creation not derived")
            elif sig == 0xA0000002 and len(payload) == 0xCC - 8:
                # ConsoleDataBlock: payload-relative = block-relative minus 8.
                # Offsets per MS-SHLLINK (Unused1/Unused2 are DWORDs).
                record["console_face_name"] = payload[36:100].decode(
                    "utf-16-le", "replace").split("\x00")[0].strip() or None
                record["console_font_size"] = _u32(payload, 24)
                record["console_font_family"] = _u32(payload, 28)
                record["console_font_weight"] = _u32(payload, 32)
                record["console_screen_buffer_size"] = (
                    f"{int.from_bytes(payload[4:6], 'little', signed=True)}x"
                    f"{int.from_bytes(payload[6:8], 'little', signed=True)}")
                record["console_window_size"] = (
                    f"{int.from_bytes(payload[8:10], 'little', signed=True)}x"
                    f"{int.from_bytes(payload[10:12], 'little', signed=True)}")
                record["console_history_buffer_size"] = _u32(payload, 120)
                record["console_history_buffers"] = _u32(payload, 124)
                record["console_quick_edit"] = bool(_u32(payload, 108))
                record["console_insert_mode"] = bool(_u32(payload, 112))
                record["console_fullscreen"] = bool(_u32(payload, 104))
                record["console_color_table"] = [
                    f"0x{_u32(payload, 132 + i * 4):08X}" for i in range(16)]
            elif sig == 0xA0000004 and len(payload) >= 4:
                record["console_code_page"] = _u32(payload, 0)
            elif sig == 0xA0000006 and len(payload) >= 8:
                record["darwin_ansi"] = payload[:260].split(b"\x00")[0] \
                    .decode("cp1252", "replace").strip() or None
                record["darwin_unicode"] = payload[260:780] \
                    .decode("utf-16-le", "replace").split("\x00")[0].strip() or None
            elif sig == 0xA0000008 and 2 <= len(payload) <= 8192:
                record["shim_layer_name"] = payload.decode(
                    "utf-16-le", "replace").split("\x00")[0].strip() or None
            elif sig == 0xA0000005 and len(payload) >= 8:
                sfid = _u32(payload, 0)
                record["special_folder_id"] = sfid
                record["special_folder_name"] = CSIDL_NAMES.get(
                    sfid, f"UNKNOWN(0x{sfid:08X})")
                record["special_folder_offset"] = _u32(payload, 4)
            elif sig in (0xA0000001, 0xA0000007) and len(payload) >= 780:
                ansi = payload[:260].split(b"\x00")[0].decode("cp1252", "replace")
                uni = payload[260:780].decode("utf-16-le", "replace").split("\x00")[0]
                env_target = (uni or ansi).strip()
                if env_target and not record["target_path"]:
                    record["target_path"] = env_target
                    record["target_source"] = "environment_variable_block"
            elif sig == 0xA0000009:
                _parse_property_store(payload, record)
            elif sig == 0xA000000B and len(payload) >= 16:
                record["known_folder_guid"] = guid_str(payload[:16])
                if len(payload) >= 20:
                    record["known_folder_offset"] = _u32(payload, 16)
            elif sig == 0xA000000C:
                _parse_vista_idlist(data, off, record)
        except (ValueError, IndexError) as exc:
            notes.append(f"{name} parse error: {exc}")
        off += size
    record["extra_data_blocks"] = sorted(blocks)


def _decode_typed_value(buf):
    """Decode a TypedPropertyValue buffer (type + 2 pad bytes + data).

    Returns (decoded, known). Known OLE variant types decode fully;
    anything else yields a bounded, labeled hex preview so no bytes are
    silently dropped. Never raises on bounded input.
    """
    if len(buf) < 4:
        return None, False
    vtype = struct.unpack_from("<H", buf, 0)[0]
    data = buf[4:]
    try:
        if vtype == 0x001F:  # VT_LPWSTR
            return data.decode("utf-16-le", "replace").split("\x00")[0], True
        if vtype == 0x001E:  # VT_LPSTR
            return data.split(b"\x00")[0].decode("cp1252", "replace"), True
        if vtype == 0x000B:  # VT_BOOL
            return bool(struct.unpack_from("<H", data, 0)[0]), True
        if vtype == 0x0003:  # VT_I4
            return struct.unpack_from("<i", data, 0)[0], True
        if vtype == 0x0013:  # VT_UI4
            return struct.unpack_from("<I", data, 0)[0], True
        if vtype == 0x0014:  # VT_I8
            return struct.unpack_from("<q", data, 0)[0], True
        if vtype == 0x0015:  # VT_UI8
            return struct.unpack_from("<Q", data, 0)[0], True
        if vtype == 0x0040:  # VT_FILETIME
            return iso(filetime_to_utc(struct.unpack_from("<Q", data, 0)[0])), True
        if vtype == 0x0048 and len(data) >= 16:  # VT_CLSID
            return guid_str(data[:16]), True
    except (struct.error, ValueError, IndexError, OverflowError, OSError):
        return None, False
    if vtype == 0:
        return None, False
    preview = data[:64].hex()
    return (f"<type 0x{vtype:04X} {preview}>" if preview
            else f"<type 0x{vtype:04X}>"), True


def _sane_prop_name(text):
    return bool(text) and len(text) <= 260 and all(
        ch.isprintable() or ch in "\t" for ch in text)


def _parse_prop_record(body, is_strings):
    """Parse one vsize-framed property record. Returns (key, value, keep).

    Framing by vsize means a bad row can never desynchronize the walk, so
    failures skip the row instead of aborting the sheet.
    """
    if len(body) < 9:
        return None, None, False
    if is_strings:
        nsize = struct.unpack_from("<I", body, 4)[0]
        if nsize == 0 or nsize > len(body) - 9:
            return None, None, False
        name = body[9:9 + nsize].decode("utf-16-le", "replace").split("\x00")[0]
        if not _sane_prop_name(name):
            return None, None, False
        val_off = 9 + nsize
        if body[val_off:val_off + 2] == b"\x00\x00":  # NameSize excluded terminator
            val_off += 2
        value, known = _decode_typed_value(body[val_off:])
        if not known:
            return None, None, False
        return name, value, True
    propid = struct.unpack_from("<I", body, 4)[0]
    value, _known = _decode_typed_value(body[9:])
    return f"[{propid}]", value, True


def _parse_property_store(payload, record):
    notes = record["notes"]
    values = {}
    guids = []
    p = 0
    while p + 24 <= len(payload):
        psize = _u32(payload, p)
        if psize == 0:
            break  # terminal
        if psize < 24 or p + psize > len(payload):
            notes.append("property store sheet overruns block; stopping")
            break
        if payload[p + 4:p + 8] != b"1SPS":
            notes.append(f"property sheet at +{p} has unknown version; stopping")
            break
        fmt_raw = payload[p + 8:p + 24]
        guids.append(guid_str(fmt_raw))
        end = p + psize
        q = p + 24
        is_strings = (fmt_raw == PROPERTY_STORE_STRINGS_FORMAT)
        while q + 9 <= end:
            vsize = _u32(payload, q)
            if vsize < 9 or q + vsize > end:
                notes.append("property record overruns sheet; stopping sheet")
                break
            key, value, keep = _parse_prop_record(payload[q:q + vsize], is_strings)
            if not keep:
                notes.append("skipped one unparseable property record")
            elif key is not None and key not in values:
                values[key] = value
            q += vsize
        p = end
    if len(values) > 100:
        notes.append(
            f"property store holds {len(values)} values; kept first 100")
        for i, key in enumerate(list(values)):
            if i >= 100:
                del values[key]
    record["property_store_values"] = dict(values)
    record["property_set_guids"] = guids
    if not record["target_path"]:
        for key in ("System.Link.TargetParsingPath", "System.ItemPathDisplay"):
            value = values.get(key)
            if value:
                record["target_path"] = value
                record["target_source"] = "property_store"
                break


def _parse_vista_idlist(data, off, record):
    size = _u32(data, off)
    if size < 10 or off + size > len(data):
        return
    idlist_off = _u16(data, off + 8)
    idlist = data[off + idlist_off:off + size]
    path, _ = parse_idlist(data, off, idlist)
    if path and not record["target_path"]:
        record["target_path"] = clean_drive_path(path)
        record["target_source"] = "vista_idlist"
        record["notes"].append("target recovered from VistaAndAboveIDListDataBlock")


def parse_lnk_builtin(path):
    """Parse an LNK file with the pure-Python engine. Raises on invalid files."""
    size = os.path.getsize(path)
    if size > MAX_SANE_FILE:
        raise ValueError(f"file too large ({size} bytes)")
    with open(path, "rb") as fh:
        data = fh.read()
    return parse_lnk_bytes(data, path, size=size)


def parse_lnk_bytes(data, path=None, size=None):
    """Parse LNK bytes with the pure-Python engine. Raises on invalid files.

    `path` is optional identity metadata: when given, it fills lnk_file /
    lnk_path and the file's own mtime/birthtime; when None (e.g. an LNK
    embedded in a Jump List stream) those fields stay None and only the
    target/forensic fields are populated. Added for Jump List reuse;
    parse_lnk_builtin() delegates here so file-based output is unchanged.
    """
    data = bytes(data)
    if size is None:
        size = len(data)
    if len(data) < 0x4C:
        raise ValueError(f"file smaller than ShellLinkHeader ({len(data)} bytes)")
    if data[:4] != LNK_SIGNATURE:
        raise ValueError("missing LNK signature")
    if data[4:20] != LNK_CLSID:
        raise ValueError("unexpected LinkCLSID")

    link_flags = _u32(data, 0x14)
    is_unicode = bool(link_flags & IS_UNICODE)

    record = {
        "lnk_file": os.path.basename(path) if path else None,
        "lnk_path": os.path.abspath(path) if path else None,
        "lnk_file_size": size,
        "header_size": None,
        "link_flags": [name for i, name in enumerate(LINK_FLAGS) if link_flags >> i & 1],
        "file_attributes": [name for i, name in enumerate(FILE_ATTRIBUTE_FLAGS)
                            if _u32(data, 0x18) >> i & 1],
        "show_command": None,
        "show_command_name": None,
        "hotkey": None,
        "hotkey_raw": None,
        "target_path": None,
        "target_source": None,
        "target_file_size": None,
        "idlist_path": None,
        "local_base_path": None,
        "common_path_suffix": None,
        "net_name": None,
        "device_name": None,
        "network_provider_type": None,
        "volume_serial_number": None,
        "volume_label": None,
        "drive_type": None,
        "machine_id": None,
        "mac_address": None,
        "droid_guid_version": None,
        "droid_creation_time_utc": None,
        "droid_creation_time_utc": None,
        "tracker_version": None,
        "droid_volume_guid": None,
        "droid_file_guid": None,
        "droid_birth_volume_guid": None,
        "droid_birth_file_guid": None,
        "known_folder_guid": None,
        "known_folder_offset": None,
        "special_folder_id": None,
        "special_folder_name": None,
        "special_folder_offset": None,
        "console_face_name": None,
        "console_font_size": None,
        "console_font_family": None,
        "console_font_weight": None,
        "console_screen_buffer_size": None,
        "console_window_size": None,
        "console_history_buffer_size": None,
        "console_history_buffers": None,
        "console_quick_edit": None,
        "console_insert_mode": None,
        "console_fullscreen": None,
        "console_color_table": None,
        "console_code_page": None,
        "darwin_ansi": None,
        "darwin_unicode": None,
        "shim_layer_name": None,
        "description": None,
        "relative_path": None,
        "working_directory": None,
        "arguments": None,
        "icon_location": None,
        "icon_file": None,
        "icon_index": None,
        "property_store_values": {},
        "property_set_guids": [],
        "extra_data_blocks": [],
        "notes": [],
        "lnk_file_accessed_utc": None,
    }

    record["header_size"] = _u32(data, 0)
    if record["header_size"] != 0x4C:
        record["notes"].append(f"unexpected ShellLinkHeader size {record['header_size']}")
    show = _u32(data, 0x3C)
    record["show_command"] = show
    record["show_command_name"] = SHOW_COMMANDS.get(show, f"UNKNOWN({show})")
    hotkey_raw = _u16(data, 0x40)
    record["hotkey_raw"] = f"0x{hotkey_raw:04X}" if hotkey_raw else None
    record["hotkey"] = decode_hotkey(hotkey_raw)

    record["target_creation_time_utc"] = iso(filetime_to_utc(_u64(data, 0x1C)))
    record["target_access_time_utc"] = iso(filetime_to_utc(_u64(data, 0x24)))
    record["target_modification_time_utc"] = iso(filetime_to_utc(_u64(data, 0x2C)))
    record["target_file_size"] = _u32(data, 0x34)
    if record["target_creation_time_utc"] is None and _u64(data, 0x1C):
        record["notes"].append(f"invalid creation timestamp 0x{_u64(data, 0x1C):X}")
    if record["target_access_time_utc"] is None and _u64(data, 0x24):
        record["notes"].append(f"invalid access timestamp 0x{_u64(data, 0x24):X}")
    if record["target_modification_time_utc"] is None and _u64(data, 0x2C):
        record["notes"].append(f"invalid modification timestamp 0x{_u64(data, 0x2C):X}")

    off = 0x4C

    if link_flags & HAS_LINK_TARGET_IDLIST:
        idlist_size = _u16(data, off)
        idlist = data[off + 2:off + 2 + idlist_size]
        if idlist_size == 0 or len(idlist) < idlist_size:
            record["notes"].append("truncated LinkTargetIDList")
        else:
            idlist_path, idlist_notes = parse_idlist(data, off, idlist)
            record["idlist_path"] = clean_drive_path(idlist_path)
            record["notes"].extend(idlist_notes)
            if idlist_path and not record["target_path"]:
                record["target_path"] = clean_drive_path(idlist_path)
                record["target_source"] = "idlist"
        off += 2 + idlist_size

    if link_flags & HAS_LINK_INFO:
        try:
            _parse_link_info(data, off, record)
        except (ValueError, IndexError, struct.error) as exc:
            record["notes"].append(f"LinkInfo error: {exc}")
        off += _u32(data, off)

    for flag, field in ((HAS_NAME, "description"), (HAS_RELATIVE_PATH, "relative_path"),
                        (HAS_WORKING_DIR, "working_directory"), (HAS_ARGUMENTS, "arguments"),
                        (HAS_ICON_LOCATION, "icon_location")):
        if not link_flags & flag:
            continue
        if off + 2 > len(data):
            record["notes"].append(f"truncated StringData ({field})")
            break
        chars = _u16(data, off)
        width = 2 if is_unicode else 1
        raw = data[off + 2:off + 2 + chars * width]
        text = (raw.decode("utf-16-le", "replace") if is_unicode
                else raw.decode("cp1252", "replace"))
        if len(raw) < chars * width:
            record["notes"].append(f"truncated StringData ({field})")
        record[field] = text.rstrip("\x00") or None
        off += 2 + chars * width

    if link_flags & HAS_ARGUMENTS and record.get("arguments"):
        record["notes"].append(f"run arguments: {record['arguments']}")

    if record.get("icon_location") and "," in record["icon_location"]:
        location, _, index = record["icon_location"].rpartition(",")
        if location and index.strip().lstrip("-").isdigit():
            record["icon_file"] = location
            record["icon_index"] = int(index.strip())

    try:
        _parse_extra_data(data, off, record)
    except (ValueError, IndexError, struct.error) as exc:
        record["notes"].append(f"ExtraData error: {exc}")

    if path is not None:
        stat = os.stat(path)
        record["lnk_file_modified_utc"] = iso(dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc))
        record["lnk_file_created_utc"] = iso(
            dt.datetime.fromtimestamp(stat.st_birthtime, dt.timezone.utc)) if hasattr(stat, "st_birthtime") else None
        record["lnk_file_accessed_utc"] = iso(dt.datetime.fromtimestamp(stat.st_atime, dt.timezone.utc))
    else:
        record["lnk_file_modified_utc"] = None
        record["lnk_file_created_utc"] = None
        record["lnk_file_accessed_utc"] = None

    record["target_exists"] = None
    if record["target_path"] and not record["target_path"].startswith("::") \
            and not record["target_path"].startswith("\\\\") \
            and not record["target_path"].startswith("http"):
        try:
            record["target_exists"] = os.path.exists(record["target_path"])
        except OSError:
            record["target_exists"] = None
    return record


# --------------------------------------------------------------------------
# pylnk3 enrichment (optional)
# --------------------------------------------------------------------------

def enrich_with_pylnk3(path, record):
    if pylnk3 is None:
        return record
    try:
        link = pylnk3.Lnk(path)
    except Exception as exc:  # noqa: BLE001 (optional dependency / untrusted input guard)
        record["notes"].append(f"pylnk3 error: {exc}")
        record["parsers_used"].append("pylnk3(failed)")
        return record

    info = getattr(link, "_link_info", None)
    if not record["target_path"]:
        for candidate, source in (
            (getattr(info, "local_base_path", None), "link_info"),
            (getattr(info, "path", None), "link_info"),
            (getattr(link, "work_dir", None), None),
        ):
            if candidate:
                record["target_path"] = candidate
                record["target_source"] = source or "pylnk3"
                break
        if not record["target_path"]:
            idlist = getattr(link, "shell_item_id_list", None)
            if idlist is not None:
                try:
                    candidate = clean_drive_path(idlist.get_path())
                    if candidate:
                        record["target_path"] = candidate
                        record["target_source"] = "idlist(pylnk3)"
                except Exception as exc:  # noqa: BLE001 (optional dependency / untrusted input guard)
                    record["notes"].append(f"pylnk3 IDList path error: {exc}")
        if not record["target_path"]:
            for block in getattr(getattr(link, "extra_data", None), "blocks", []):
                if type(block).__name__ in (
                        "ExtraData_EnvironmentVariableDataBlock",
                        "ExtraData_IconEnvironmentDataBlock"):
                    value = (getattr(block, "target_unicode", None) or
                             getattr(block, "target_ansi", None) or "").split("\x00")[0]
                    if value:
                        record["target_path"] = value
                        record["target_source"] = "environment_variable_block"
                        break

    for field, attr, fallback in (
        ("description", "description", None),
        ("relative_path", "relative_path", None),
        ("working_directory", "work_dir", None),
        ("arguments", "arguments", None),
        ("icon_location", "icon", None),
    ):
        if not record.get(field):
            value = getattr(link, attr, None)
            if value:
                record[field] = value
            elif fallback:
                record[field] = fallback

    if info is not None:
        if record["volume_serial_number"] is None and getattr(info, "drive_serial", None) is not None:
            record["volume_serial_number"] = f"0x{info.drive_serial:08X}"
        if record["drive_type"] is None and getattr(info, "drive_type", None):
            record["drive_type"] = info.drive_type
        if record["volume_label"] is None and getattr(info, "volume_label", None):
            record["volume_label"] = info.volume_label
    if record["machine_id"] is None and getattr(link, "machine_id", None):
        record["machine_id"] = str(link.machine_id)

    try:
        record["extra_data_blocks"] = sorted(set(record["extra_data_blocks"]) | {
            type(block).__name__ for block in link.extra_data.blocks})
    except Exception as exc:  # noqa: BLE001 (optional dependency / untrusted input guard)
        record["notes"].append(f"pylnk3 ExtraData error: {exc}")
    return record


# --------------------------------------------------------------------------
# timeline construction
# --------------------------------------------------------------------------

def make_events(record):
    events = []
    for label, field in (
        ("Target Creation", "target_creation_time_utc"),
        ("Target Access", "target_access_time_utc"),
        ("Target Modification", "target_modification_time_utc"),
        ("LNK File Modified", "lnk_file_modified_utc"),
        ("LNK File Created", "lnk_file_created_utc"),
    ):
        stamp = record.get(field)
        if not stamp:
            continue
        events.append({
            "timestamp": stamp,
            "timestamp_type": label,
            "source": "LNK",
            "artifact_type": "windows_shortcut",
            "lnk_file": record["lnk_file"],
            "lnk_path": record["lnk_path"],
            "target_path": record["target_path"],
            "details": {
                "target_source": record["target_source"],
                "target_exists": record["target_exists"],
                "header_size": record["header_size"],
                "show_command": record["show_command"],
                "show_command_name": record["show_command_name"],
                "hotkey": record["hotkey"],
                "hotkey_raw": record["hotkey_raw"],
                "local_base_path": record["local_base_path"],
                "common_path_suffix": record["common_path_suffix"],
                "net_name": record["net_name"],
                "device_name": record["device_name"],
                "network_provider_type": record["network_provider_type"],
                "volume_serial_number": record["volume_serial_number"],
                "volume_label": record["volume_label"],
                "drive_type": record["drive_type"],
                "machine_id": record["machine_id"],
                "mac_address": record["mac_address"],
                "droid_guid_version": record["droid_guid_version"],
                "droid_creation_time_utc": record["droid_creation_time_utc"],
                "tracker_version": record["tracker_version"],
                "droid_file_guid": record["droid_file_guid"],
                "droid_volume_guid": record["droid_volume_guid"],
                "droid_birth_file_guid": record["droid_birth_file_guid"],
                "droid_birth_volume_guid": record["droid_birth_volume_guid"],
                "known_folder_guid": record["known_folder_guid"],
                "known_folder_offset": record["known_folder_offset"],
                "special_folder_id": record["special_folder_id"],
                "special_folder_name": record["special_folder_name"],
                "special_folder_offset": record["special_folder_offset"],
                "console_face_name": record["console_face_name"],
                "console_font_size": record["console_font_size"],
                "console_font_family": record["console_font_family"],
                "console_font_weight": record["console_font_weight"],
                "console_screen_buffer_size": record["console_screen_buffer_size"],
                "console_window_size": record["console_window_size"],
                "console_history_buffer_size": record["console_history_buffer_size"],
                "console_history_buffers": record["console_history_buffers"],
                "console_quick_edit": record["console_quick_edit"],
                "console_insert_mode": record["console_insert_mode"],
                "console_fullscreen": record["console_fullscreen"],
                "console_color_table": record["console_color_table"],
                "console_code_page": record["console_code_page"],
                "darwin_ansi": record["darwin_ansi"],
                "darwin_unicode": record["darwin_unicode"],
                "shim_layer_name": record["shim_layer_name"],
                "target_file_size": record["target_file_size"],
                "description": record["description"],
                "relative_path": record["relative_path"],
                "working_directory": record["working_directory"],
                "arguments": record["arguments"],
                "icon_location": record["icon_location"],
                "icon_file": record["icon_file"],
                "icon_index": record["icon_index"],
                "property_store_values": record["property_store_values"],
                "property_set_guids": record["property_set_guids"],
                "extra_data_blocks": record["extra_data_blocks"],
                "lnk_file_accessed_utc": record["lnk_file_accessed_utc"],
                "parsers_used": record["parsers_used"],
            },
        })
    return events


# --------------------------------------------------------------------------
# file discovery and table rendering
# --------------------------------------------------------------------------

def iter_lnk_files(root, recursive):
    if recursive:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames):
                if name.lower().endswith(".lnk"):
                    yield os.path.join(dirpath, name)
    else:
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            if os.path.isfile(full) and name.lower().endswith(".lnk"):
                yield full


def truncate(text, width):
    if not text:
        return "-"
    text = str(text)
    return text if len(text) <= width else text[:width - 3] + "..."


def render_table(rows, headers, use_tabulate):
    if not rows:
        return "(no parsed artifacts)"
    if use_tabulate and tabulate is not None:
        try:
            return tabulate(rows, headers=headers, tablefmt="grid")
        except Exception:  # noqa: BLE001 (optional dependency / untrusted input guard)
            return _plain_table(rows, headers)
    return _plain_table(rows, headers)


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
        description="Parse Windows LNK shortcuts into a chronological JSON timeline.")
    parser.add_argument("directory", nargs="?", default="samples",
                        help="directory containing .lnk files (default: samples)")
    parser.add_argument("-o", "--output", default="lnk_timeline.json",
                        help="output JSON file (default: lnk_timeline.json)")
    parser.add_argument("--flat", action="store_true",
                        help="do not recurse into subdirectories (default: recursive)")
    parser.add_argument("--no-pylnk3", action="store_true",
                        help="disable the optional pylnk3 enrichment engine")
    parser.add_argument("--no-tabulate", action="store_true",
                        help="disable tabulate and use the built-in table renderer")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress the console summary table")
    args = parser.parse_args(argv)

    if pylnk3 is not None and args.no_pylnk3:
        globals()["pylnk3"] = None

    root = os.path.abspath(args.directory)
    if not os.path.isdir(root):
        print(f"[!] not a directory: {root}", file=sys.stderr)
        return 2

    engine = ["builtin"]
    if pylnk3 is not None:
        engine.append("pylnk3")

    records, skipped, events = [], [], []
    for path in iter_lnk_files(root, recursive=not args.flat):
        try:
            record = parse_lnk_builtin(path)
            record["parsers_used"] = ["builtin"]
        except Exception as exc:  # noqa: BLE001 (optional dependency / untrusted input guard)
            skipped.append({"file": os.path.abspath(path),
                            "error_type": type(exc).__name__,
                            "error": str(exc)})
            print(f"[!] skipped {path} ({type(exc).__name__}: {exc})", file=sys.stderr)
            continue
        if pylnk3 is not None:
            enrich_with_pylnk3(path, record)
            if "pylnk3(failed)" not in record["parsers_used"]:
                record["parsers_used"].append("pylnk3")
        records.append(record)
        events.extend(make_events(record))

    events.sort(key=lambda e: (e["timestamp"], e["lnk_path"], e["timestamp_type"]))

    machines = sorted({r["machine_id"] for r in records if r["machine_id"]})
    document = {
        "metadata": {
            "tool": TOOL,
            "version": VERSION,
            "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "target_directory": root,
            "scan_mode": "flat" if args.flat else "recursive",
            "parser_engine": engine,
            "timestamps_format": "ISO 8601 UTC",
            "counts": {
                "lnk_files_found": len(records) + len(skipped),
                "lnk_files_parsed": len(records),
                "lnk_files_failed": len(skipped),
                "timeline_events": len(events),
                "unique_targets": len({r["target_path"] for r in records if r["target_path"]}),
                "machines_observed": machines,
                "volume_serials": sorted({r["volume_serial_number"] for r in records
                                          if r["volume_serial_number"]}),
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
        rows = [[i + 1, truncate(r["lnk_file"], 24), truncate(r["target_path"], 52),
                 truncate(r["target_creation_time_utc"], 21),
                 truncate(r["target_modification_time_utc"], 21),
                 truncate(r["volume_serial_number"], 12),
                 truncate(r["machine_id"], 18)]
                for i, r in enumerate(records)]
        print(f"\n[{TOOL}] {root} -> {out_path}")
        print(render_table(rows, ["#", "LNK File", "Target Path",
                                  "Target Created (UTC)", "Target Modified (UTC)",
                                  "Volume Serial", "Machine ID"],
                           use_tabulate=not args.no_tabulate))
        print()
        print(f"[+] {len(records)} LNK parsed, {len(skipped)} skipped, "
              f"{len(events)} timeline events -> {out_path}")
        if machines:
            print(f"[+] machines observed: {', '.join(machines)}")
        if document["metadata"]["counts"]["volume_serials"]:
            print("[+] volume serials: "
                  + ", ".join(document["metadata"]["counts"]["volume_serials"]))
        if skipped:
            print(f"[!] {len(skipped)} file(s) could not be parsed (see 'skipped' in JSON)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
