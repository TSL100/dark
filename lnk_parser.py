#!/usr/bin/env python3
"""
lnk_parser.py - PoC LNK (.lnk) parser -> chronological JSON timeline (SANS FOR500)

Extracts per .lnk file: target path, header timestamps, MachineID (TrackerData),
Volume Serial (LinkInfo/VolumeID). Uses pylnk3 when available and falls back to a
pure-Python MS-SHLLINK parser, so the script runs even without native bindings.
"""

import argparse
import datetime as dt
import json
import struct
import sys
from pathlib import Path

try:
    import pylnk3
    HAVE_PYLNK3 = True
except Exception:
    pylnk3 = None
    HAVE_PYLNK3 = False

from tabulate import tabulate

FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
EXTRA_TRACKER = 0xA0000003

# Forensic artifacts contain arbitrary Unicode paths; keep the console from
# crashing on codepages like cp1252.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def filetime_to_iso(value):
    if not value:
        return None
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.isoformat()
    try:
        return (FILETIME_EPOCH + dt.timedelta(microseconds=int(value) // 10)).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _cstr(buf, off, unicode_flag):
    if unicode_flag:
        end = off
        while end + 2 <= len(buf) and buf[end:end + 2] != b"\x00\x00":
            end += 2
        return buf[off:end].decode("utf-16-le", "replace")
    end = buf.find(b"\x00", off)
    return buf[off:end if end != -1 else len(buf)].decode("cp1252", "replace")


def _tracker_machine_id(data: bytes, off: int, size: int):
    # MachineID is a null-terminated string in the TrackerDataBlock.
    # The spec puts it at block+12; real-world writers pad differently
    # (WScript.Shell writes 4 extra zero bytes -> block+16, some -> block+22).
    # Try all offsets, keep the longest printable result.
    candidates = []
    for delta in (12, 16, 22):
        if off + delta + 16 <= off + size:
            raw = data[off + delta:off + delta + 16]
            s = raw.split(b"\x00")[0].decode("cp1252", "replace").strip()
            if s and s.isprintable():
                candidates.append(s)
    return max(candidates, key=len) if candidates else None


def _is_extra_block(data: bytes, off: int) -> bool:
    # A valid ExtraData block: BlockSize >= 8, in-bounds, and a signature
    # in the 0xA00000xx range (EnvironmentVariable, Tracker, Icon, ...).
    if off + 8 > len(data):
        return False
    size = struct.unpack_from("<I", data, off)[0]
    sig = struct.unpack_from("<I", data, off + 4)[0]
    return 8 <= size <= len(data) - off and 0xA0000001 <= sig <= 0xA00000FF


def parse_lnk_pure(path: Path):
    data = path.read_bytes()
    if len(data) < 0x4C:
        raise ValueError("file smaller than a LNK header")
    if struct.unpack_from("<I", data, 0)[0] != 0x4C:
        raise ValueError("invalid Shell Link header size")

    flags = struct.unpack_from("<I", data, 0x14)[0]
    created = struct.unpack_from("<Q", data, 0x1C)[0]
    accessed = struct.unpack_from("<Q", data, 0x24)[0]
    written = struct.unpack_from("<Q", data, 0x2C)[0]

    off = 0x4C
    target = machine_id = vol_serial = None

    if flags & 0x01:  # ShellItemIDList
        off += struct.unpack_from("<H", data, off)[0]
        # WScript.Shell writes the terminal 0x0000 IDList item without counting
        # it in the size field, so skip it before LinkInfo (validated by size check)
        if (flags & 0x02 and off + 6 <= len(data)
                and data[off:off + 2] == b"\x00\x00"
                and 0x1C <= struct.unpack_from("<I", data, off + 2)[0] <= len(data) - off - 2):
            off += 2

    if flags & 0x02:  # LinkInfo
        li_size = struct.unpack_from("<I", data, off)[0]
        li_hdr_size = struct.unpack_from("<I", data, off + 4)[0]
        li_flags = struct.unpack_from("<I", data, off + 8)[0]
        uni = li_hdr_size >= 0x24
        if li_flags & 0x01:  # VolumeIDAndLocalBasePath
            vol_off = struct.unpack_from("<I", data, off + 12)[0]
            base_off = struct.unpack_from("<I", data, off + 16)[0]
            vol_serial = f"{struct.unpack_from('<I', data, off + vol_off + 8)[0]:08X}"
            target = _cstr(data, off + base_off, uni)
        elif li_flags & 0x02:  # CommonNetworkRelativeLink
            net_off = struct.unpack_from("<I", data, off + 20)[0]
            share_off = struct.unpack_from("<I", data, off + net_off + 20)[0]
            suffix_off = struct.unpack_from("<I", data, off + 24)[0]
            share = _cstr(data, off + net_off + share_off, uni)
            suffix = _cstr(data, off + suffix_off, uni)
            if share:
                target = share.rstrip("\\") + "\\" + suffix.lstrip("\\")
            else:
                target = suffix or None
        off += li_size

    if flags & 0x04:  # StringData (name, relative, workdir, args, icon)
        for _ in range(5):
            # The spec requires all 5 strings when the flag is set, but real
            # writers omit trailing empty ones, so stop when ExtraData starts.
            if _is_extra_block(data, off):
                break
            if off + 2 > len(data):
                break
            off += 2 + struct.unpack_from("<H", data, off)[0] * 2
            if off > len(data):
                raise ValueError("StringData runs past end of file")

    if flags & 0x08:  # ExtraData
        end = len(data)
        while off + 8 <= end:
            size = struct.unpack_from("<I", data, off)[0]
            sig = struct.unpack_from("<I", data, off + 4)[0]
            if size < 8 or off + size > end:
                break
            if sig == EXTRA_TRACKER:
                machine_id = _tracker_machine_id(data, off, size)
            off += size
        if machine_id is None:
            # Fallback: WScript.Shell pads a stray length-prefixed string
            # before the first block, so scan for the TrackerData signature
            # and validate the block size to reject Droid false positives.
            needle = struct.pack("<I", EXTRA_TRACKER)
            pos = data.find(needle, off)
            while pos != -1:
                block_start = pos - 4
                if block_start >= 0:
                    blk_size = struct.unpack_from("<I", data, block_start)[0]
                    if 8 <= blk_size <= end - block_start:
                        machine_id = _tracker_machine_id(data, block_start, blk_size)
                        if machine_id:
                            break
                pos = data.find(needle, pos + 1)

    return {
        "target_path": target,
        "created": filetime_to_iso(created),
        "accessed": filetime_to_iso(accessed),
        "modified": filetime_to_iso(written),
        "machine_id": machine_id,
        "volume_serial": vol_serial,
    }


def parse_lnk(path: Path):
    if HAVE_PYLNK3:
        try:
            l = pylnk3.parse(str(path))
            serial = getattr(l, "volume_serial_number", None)
            return {
                "target_path": l.base_path or l.network_path,
                "created": filetime_to_iso(l.creation_time),
                "accessed": filetime_to_iso(l.accessed_time),
                "modified": filetime_to_iso(l.modified_time),
                "machine_id": getattr(l, "machine_id", None) or None,
                "volume_serial": f"{serial:08X}" if isinstance(serial, int) else serial,
            }
        except Exception:
            pass  # fall back to the pure parser for this file
    return parse_lnk_pure(path)


def build_timeline(root: Path, recursive: bool):
    events, rows, errors = [], [], []
    for p in root.glob("**/*.lnk" if recursive else "*.lnk"):
        try:
            st = p.stat()
            info = parse_lnk(p)
        except Exception as e:
            errors.append({"file": str(p), "error": str(e)})
            continue

        meta = {
            "lnk_file": p.name,
            "lnk_path": str(p),
            "machine_id": info["machine_id"],
            "volume_serial": info["volume_serial"],
        }
        for event, ts in (
            ("Target Created", info["created"]),
            ("Target Accessed", info["accessed"]),
            ("Target Modified", info["modified"]),
            ("LNK File Modified", dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).isoformat()),
        ):
            if not ts:
                continue
            events.append({
                "timestamp": ts,
                "event": event,
                "source": "LNK",
                "target_path": info["target_path"],
                "details": meta,
            })
        rows.append([p.name, info["target_path"] or "-", info["accessed"], info["modified"], info["machine_id"] or "-"])

    events.sort(key=lambda e: e["timestamp"])
    return events, rows, errors


def main():
    ap = argparse.ArgumentParser(description="Parse .lnk files into a chronological JSON timeline (FOR500 PoC)")
    ap.add_argument("target", nargs="?", default=".", help="directory containing .lnk files")
    ap.add_argument("-o", "--output", default="lnk_timeline.json", help="output JSON file")
    ap.add_argument("--flat", action="store_true", help="do not recurse into subdirectories")
    args = ap.parse_args()

    root = Path(args.target)
    if not root.is_dir():
        sys.exit(f"[!] Not a directory: {root}")

    print(f"[*] Parser: {'pylnk3 (with pure-Python fallback)' if HAVE_PYLNK3 else 'pure-Python (MS-SHLLINK)'}")
    events, rows, errors = build_timeline(root, recursive=not args.flat)

    Path(args.output).write_text(json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8")

    if rows:
        print(tabulate(rows, headers=["LNK File", "Target Path", "Accessed (UTC)", "Modified (UTC)", "Machine ID"], tablefmt="grid"))
    print(f"\n[+] {len(events)} timeline events -> {args.output}")
    if errors:
        print(f"[!] {len(errors)} file(s) skipped (corrupted/locked/unreadable):")
        for e in errors:
            print(f"    - {e['file']}: {e['error']}")


if __name__ == "__main__":
    main()
