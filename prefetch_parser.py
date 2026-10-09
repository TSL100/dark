#!/usr/bin/env python3
"""
prefetch_parser.py - Windows Prefetch (.pf) parser -> chronological JSON timeline.

DFIR PoC engine, companion to lnk_forensics.py. Parses Windows Prefetch files
(C:\\Windows\\Prefetch\\*.pf) and emits the SAME standardized event/JSON schema
used by the LNK timeline, so the existing PySide6 viewer (dfir_timeline_ui.py)
ingests Prefetch output with zero GUI changes (it already detects
source == "Prefetch").

Supported formats
-----------------
* Uncompressed SCCA files (anosognosia: "SCCA" magic at offset 4):
  versions 17 (XP/2003), 23 (Vista/7). Some v23 (Win8-era) files on disk are
  already MAM-compressed; those are handled by the path below.
* MAM-compressed files (magic b"MAM\\x04" at offset 0, MS-XCA LZXPRESS+Huffman):
  versions 23 (Win8), 26 (8.x), 30 (Win10), 31 (Win11). Decompression tiers:
    1. Windows ntdll RtlDecompressBufferEx via ctypes (no dependency, Win8+ host).
    2. Built-in pure-Python MS-XCA LZ77+Huffman decoder (cross-platform fallback).
  If both fail, the file is reported under "skipped" (never silently degraded).

High-value fields extracted (never guessed, always bounds-checked)
------------------------------------------------------------------
* Executable name (header, UTF-16LE) + prefetch hash (header + filename check).
* Run count (version-dependent offset, incl. Win10 v30 variant-1/variant-2).
* Last execution timestamps: 1 slot (v17/v23) or up to 8 slots (v26/v30/v31),
  most-recent-first, as FILETIME -> ISO 8601 UTC.
* Referenced file paths (filename-strings section) + volume device paths,
  volume creation times and volume serial numbers.

Each non-zero execution slot becomes one timeline event with:
    source="Prefetch", standardized UTC timestamp, and details.machine_id
(Prefetch stores no host identifier, so machine_id is supplied with
--machine-id / defaults to None -> GUI shows "N/A", same as LNK unknown hosts).

Event schema (mirrors lnk_forensics.make_events exactly)
--------------------------------------------------------
    {
      "timestamp": str,            # ISO 8601 UTC
      "timestamp_type": str,       # Last Execution | Prior Execution #N |
                                   # Prefetch File Modified | Prefetch File Created
      "source": "Prefetch",
      "artifact_type": "prefetch",
      "prefetch_file": str,        # e.g. NOTEPAD.EXE-A3B4C5D6.pf
      "prefetch_path": str,        # absolute path
      "prefetch_name": str,        # alias read by the GUI normalizer
      "artifact_name": str,        # alias read by the GUI normalizer
      "executable_name": str,      # e.g. NOTEPAD.EXE
      "target_path": str,          # executable name (pivot column; full
                                   # referenced paths live in details)
      "details": {
        "executable_name": str,
        "prefetch_hash": "0x........",
        "run_count": int,
        "run_index": int,          # 0 == most recent execution slot
        "total_runs_recorded": int,
        "all_execution_times_utc": [str, ...],
        "pf_version": int,
        "windows_version_hint": str,
        "file_size": int,
        "is_compressed_mam": bool,
        "referenced_files": [str, ...],
        "referenced_files_count": int,
        "referenced_files_truncated": bool,
        "volumes": [{"device_path": str, "creation_time_utc": str|None,
                     "serial_number": "0x........"}],
        "machine_id": str|None,
        "parsers_used": [str, ...],
      },
    }

Merging with an LNK timeline (GUI loads one file; combine first)
----------------------------------------------------------------
    python -c "import json; a=json.load(open('lnk_timeline.json')); \\
      b=json.load(open('prefetch_timeline.json')); \\
      ev=sorted(a['events']+b['events'], key=lambda e:e['timestamp']); \\
      json.dump({'metadata':{**a['metadata'],'merged_with':'prefetch_timeline.json',\\
      'counts':{**a['metadata']['counts'],'timeline_events':len(ev)}},\\
      'events':ev,'artifacts':a['artifacts']+b['artifacts'],\\
      'skipped':a['skipped']+b['skipped']}, open('merged_timeline.json','w'), indent=2)"

Usage:
    python prefetch_parser.py [PATH] [-o OUTPUT.json] [--flat]
                              [--machine-id HOST] [-q]

    PATH may be a directory (scanned for *.pf) or a single .pf file.

Dependencies: Python 3.8+ standard library only (struct/datetime/json/os/
argparse/ctypes-on-Windows). No pip packages required.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import struct
import sys

TOOL = "prefetch_parser.py"
VERSION = "1.1.0"

FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
MAX_SANE_FILE = 64 * 1024 * 1024          # refuse absurd .pf inputs
MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024  # memory-bomb guard for MAM payloads
MAX_REFERENCED_FILES = 5000               # cap for the referenced-paths list
MAX_DIR_STRINGS = 5000                  # cap for directory strings per volume
MAX_VOLUMES = 32                          # sanity cap for volume entries

SCCA_MAGIC = b"SCCA"
MAM_MAGIC = b"MAM\x04"
PF_VERSIONS = (17, 23, 26, 30, 31)

WINDOWS_HINT = {
    17: "Windows XP/2003",
    23: "Windows Vista/7",
    26: "Windows 8.x",
    30: "Windows 10",
    31: "Windows 11",
}

# File-metrics-array offset identifies the Win10 v30 layout variant
# (libscca: variant 1 -> 0x130 / run count at file offset 0xD0,
#  variant 2 -> 0x128 / run count at file offset 0xC8; v31 follows variant 2).
METRICS_OFF_V30_VARIANT2 = 0x128

VOLUME_ENTRY_SIZE = {17: 40, 23: 104, 26: 104, 30: 96, 31: 96}

COMPRESSION_FORMAT_XPRESS_HUFF = 4  # ntdll RtlDecompressBufferEx format id


# --------------------------------------------------------------------------
# errors + small binary helpers
# --------------------------------------------------------------------------

class PrefetchParseError(ValueError):
    """Raised when a Prefetch file is invalid, truncated, or unsupported."""


class MAMDecompressionError(PrefetchParseError):
    """Raised when an MAM/Xpress payload cannot be decompressed."""


def _u16(data, off):
    if off < 0 or off + 2 > len(data):
        raise PrefetchParseError(f"unexpected end of data at offset 0x{off:X}")
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    if off < 0 or off + 4 > len(data):
        raise PrefetchParseError(f"unexpected end of data at offset 0x{off:X}")
    return struct.unpack_from("<I", data, off)[0]


def _u64(data, off):
    if off < 0 or off + 8 > len(data):
        raise PrefetchParseError(f"unexpected end of data at offset 0x{off:X}")
    return struct.unpack_from("<Q", data, off)[0]


def filetime_to_utc(value):
    """FILETIME (100ns ticks since 1601-01-01 UTC) -> aware UTC datetime, or None."""
    if not value:
        return None
    try:
        return FILETIME_EPOCH + dt.timedelta(microseconds=value // 10)
    except (OverflowError, OSError, ValueError):
        return None


def iso(dtobj):
    return dtobj.astimezone(dt.timezone.utc).isoformat() if dtobj else None


# --------------------------------------------------------------------------
# MS-XCA LZ77+Huffman (LZXPRESS Huffman) decompression
# --------------------------------------------------------------------------
# Implements [MS-XCA] section 2.2.4 "LZ77+Huffman Decompression Algorithm
# Details": each 64 KiB block starts with a 256-byte Huffman table (bit length
# of each of the 512 symbols, low nibble = symbol 2*i, high nibble = 2*i+1),
# followed by a Huffman-coded stream of literals (0-255), end-of-stream (256)
# and matches (257-511). Bit stream is read MSB-first out of little-endian
# u16 words. Used as the cross-platform fallback when ntdll is unavailable.

_DECODE_BITS = 15
_DECODE_SIZE = 1 << _DECODE_BITS  # 32768
_BLOCK_OUT = 65536


def xpress_huffman_decompress(data, expected_size):
    """Decompress an MS-XCA LZ77+Huffman stream (pure Python, no dependencies).

    `data` is the raw compressed payload (MAM header already stripped);
    `expected_size` is the uncompressed size from the MAM header and is used
    for termination checks and as a memory-bomb guard. Returns bytes.
    Raises MAMDecompressionError on any invalid/truncated input.
    """
    data = bytes(data)
    total = len(data)
    if expected_size <= 0 or expected_size > MAX_DECOMPRESSED_BYTES:
        raise MAMDecompressionError(
            f"implausible MAM uncompressed size {expected_size}")
    if total == 0:
        raise MAMDecompressionError("empty MAM payload")

    out = bytearray()
    pos = 0
    while True:
        # --- block prologue: need a full Huffman table -------------------
        if total - pos < 256:
            if len(out) == expected_size:
                return bytes(out)  # trailing terminator bytes, done
            raise MAMDecompressionError(
                f"truncated MAM stream: {total - pos} byte(s) left, "
                f"produced {len(out)} of {expected_size} expected bytes")
        table = data[pos:pos + 256]
        pos += 256

        bitlen = [0] * 512
        for i in range(256):
            byte = table[i]
            bitlen[2 * i] = byte & 0x0F
            bitlen[2 * i + 1] = (byte >> 4) & 0x0F

        # Canonical decoding table: 2^15 entries, symbols ordered by
        # (bit length, symbol value); a symbol of length X owns 2^(15-X)
        # consecutive entries. Must fill the table exactly.
        decode = [0] * _DECODE_SIZE
        cur = 0
        for length in range(1, 16):
            span = 1 << (_DECODE_BITS - length)
            for sym in range(512):
                if bitlen[sym] == length:
                    if cur + span > _DECODE_SIZE:
                        raise MAMDecompressionError(
                            "invalid Huffman table (overflow)")
                    for k in range(span):
                        decode[cur + k] = sym
                    cur += span
        if cur != _DECODE_SIZE:
            raise MAMDecompressionError(
                f"invalid Huffman table (covers {cur} of {_DECODE_SIZE} entries)")

        # --- bit-reader priming: 32-bit register, >=16 bits buffered -------
        # NOTE (pad contract): the reader refills EAGERLY in 2-byte units, exactly
        # like [MS-XCA] 2.2.4. Encoders therefore pad each block's bitstream so the
        # final refill lands inside the buffer (real Prefetch files do; see the
        # 2-byte block terminator in libscca). A minimal even-length stream would
        # over-read by one refill, so writers must emit pad bytes.
        if total - pos < 4:
            if len(out) == expected_size:
                return bytes(out)
            raise MAMDecompressionError("truncated Huffman bitstream")

        def _r16(at):
            if at + 2 > total:
                raise MAMDecompressionError("bitstream read past end of input")
            return data[at] | (data[at + 1] << 8)

        nextbits = ((_r16(pos) << 16) | _r16(pos + 2)) & 0xFFFFFFFF
        pos += 4
        extra = 16
        block_end = len(out) + _BLOCK_OUT

        # --- symbol loop ----------------------------------------------------
        while len(out) < block_end:
            sym = decode[nextbits >> 17]
            lbits = bitlen[sym]
            nextbits = (nextbits << lbits) & 0xFFFFFFFF
            extra -= lbits
            if extra < 0:
                nextbits |= _r16(pos) << (-extra)
                nextbits &= 0xFFFFFFFF
                extra += 16
                pos += 2
            if sym < 256:
                out.append(sym)
                if len(out) > expected_size + _BLOCK_OUT:
                    raise MAMDecompressionError("decompressed output overrun")
            elif sym == 256:
                # End-of-stream: strict success is input-exhausted + size-exact.
                # Tolerate a short (< 256 bytes, i.e. not another Huffman table)
                # pad/trailer tail so files with block-terminator padding still
                # verify instead of failing on `pos` being 2 bytes short.
                if len(out) == expected_size and (pos >= total or total - pos < 256):
                    return bytes(out)
                raise MAMDecompressionError(
                    "unexpected end-of-stream marker "
                    f"(output {len(out)}/{expected_size}, input {pos}/{total})")
            else:
                match = sym - 256
                length = match & 15
                offbits = match >> 4
                if length == 15:
                    if pos >= total:
                        raise MAMDecompressionError("truncated match length")
                    length = data[pos]
                    pos += 1
                    if length == 255:
                        length = _r16(pos)
                        pos += 2
                        if length < 15:
                            raise MAMDecompressionError(
                                "invalid extended match length")
                        length -= 15
                    length += 15
                length += 3
                if offbits:
                    offset = (nextbits >> (32 - offbits)) + (1 << offbits)
                else:
                    offset = 1
                nextbits = (nextbits << offbits) & 0xFFFFFFFF
                extra -= offbits
                if extra < 0:
                    nextbits |= _r16(pos) << (-extra)
                    nextbits &= 0xFFFFFFFF
                    extra += 16
                    pos += 2
                if offset < 1 or offset > len(out):
                    raise MAMDecompressionError(
                        f"invalid match offset {offset} at output {len(out)}")
                if len(out) + length > expected_size + _BLOCK_OUT:
                    raise MAMDecompressionError("decompressed output overrun")
                for _ in range(length):  # byte-at-a-time: length may exceed offset
                    out.append(out[len(out) - offset])
        # Block emitted 64 KiB: fall through to the next Huffman table.
        if len(out) == expected_size and pos >= total:
            return bytes(out)


def _mam_decompress_ntdll(payload, expected_size):
    """Decompress with Windows ntdll RtlDecompressBufferEx (XPRESS_HUFF).

    Dependency-free on Windows 8+ analyst hosts. Raises
    MAMDecompressionError on any failure so the caller can fall back.
    """
    import ctypes

    try:
        ntdll = ctypes.windll.ntdll
    except Exception as exc:  # non-Windows or locked-down host
        raise MAMDecompressionError(f"ntdll unavailable: {exc}")

    ntdll.RtlGetCompressionWorkSpaceSize.argtypes = [
        ctypes.c_ushort, ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong)]
    ntdll.RtlGetCompressionWorkSpaceSize.restype = ctypes.c_ulong
    ntdll.RtlDecompressBufferEx.argtypes = [
        ctypes.c_ushort, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
        ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    ntdll.RtlDecompressBufferEx.restype = ctypes.c_ulong

    workspace_needed = ctypes.c_ulong()
    fragment_needed = ctypes.c_ulong()
    status = ntdll.RtlGetCompressionWorkSpaceSize(
        COMPRESSION_FORMAT_XPRESS_HUFF,
        ctypes.byref(workspace_needed), ctypes.byref(fragment_needed))
    if status != 0:
        raise MAMDecompressionError(
            f"RtlGetCompressionWorkSpaceSize failed: 0x{status:08X}")

    workspace = ctypes.create_string_buffer(workspace_needed.value or 1)
    out_buf = ctypes.create_string_buffer(expected_size)
    in_buf = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
    final_size = ctypes.c_ulong()
    status = ntdll.RtlDecompressBufferEx(
        COMPRESSION_FORMAT_XPRESS_HUFF,
        out_buf, expected_size,
        in_buf, len(payload),
        ctypes.byref(final_size), workspace)
    if status != 0:
        raise MAMDecompressionError(
            f"RtlDecompressBufferEx failed: 0x{status:08X}")
    return bytes(out_buf.raw[:final_size.value])


def mam_decompress(payload, expected_size, notes, parsers_used):
    """Tiered MAM decompression: ntdll (Windows) -> pure-Python MS-XCA.

    Appends the successful engine to `parsers_used`. Raises
    MAMDecompressionError mentioning every failed tier.
    """
    failures = []
    if sys.platform == "win32":
        try:
            result = _mam_decompress_ntdll(payload, expected_size)
            parsers_used.append("ntdll(xpress-huff)")
            return result
        except Exception as exc:  # noqa: BLE001 - fall through to pure Python
            failures.append(f"ntdll: {exc}")
    try:
        result = xpress_huffman_decompress(payload, expected_size)
        parsers_used.append("builtin(xpress-huff)")
        return result
    except Exception as exc:  # noqa: BLE001 - reported via skipped entry
        failures.append(f"builtin xpress-huff: {exc}")
    raise MAMDecompressionError("MAM decompression failed [" + "; ".join(failures) + "]")


# --------------------------------------------------------------------------
# SCCA (uncompressed Prefetch) parsing
# --------------------------------------------------------------------------

def _parse_filename_strings(data, fn_off, fn_size, notes):
    """Split the filename-strings blob into referenced paths (order kept)."""
    if fn_size == 0:
        return []
    if fn_off <= 0 or fn_off + fn_size > len(data):
        notes.append(
            f"filename-strings section [off=0x{fn_off:X} size={fn_size}] "
            "out of bounds; referenced paths unavailable")
        return []
    blob = data[fn_off:fn_off + fn_size]
    try:
        text = blob.decode("utf-16-le", "replace")
    except (ValueError, OverflowError) as exc:
        notes.append(f"filename-strings decode error: {exc}")
        return []
    paths = [s for s in text.split("\x00") if s]
    if len(paths) > MAX_REFERENCED_FILES:
        notes.append(
            f"referenced-files list capped at {MAX_REFERENCED_FILES} "
            f"of {len(paths)} entries")
        return paths[:MAX_REFERENCED_FILES], True
    return paths, False


def _parse_dir_strings(data, vol_off, vol_size, dir_rel, count, notes, tag):
    """Parse NUL-terminated UTF-16 directory strings of one volume entry."""
    dirs = []
    if count == 0:
        return dirs
    base = vol_off + dir_rel
    end = vol_off + vol_size
    if dir_rel <= 0 or base >= end:
        notes.append(f"{tag}: directory strings offset out of bounds; skipped")
        return dirs
    if count > MAX_DIR_STRINGS:
        notes.append(f"{tag}: directory count {count} capped at {MAX_DIR_STRINGS}")
        count = MAX_DIR_STRINGS
    pos = base
    for _ in range(count):
        chars = bytearray()
        complete = False
        while pos + 2 <= end and pos + 2 <= len(data):
            unit = data[pos:pos + 2]
            pos += 2
            if unit == b"\x00\x00":
                complete = True
                break
            chars += unit
        if not complete:
            notes.append(f"{tag}: directory strings truncated")
            break
        text = bytes(chars).decode("utf-16-le", "replace")
        if text:
            dirs.append(text)
    return dirs


def _parse_volumes(data, vol_off, vol_count, vol_size, entry_size, notes):
    """Parse volume-information entries (device path, creation, serial)."""
    volumes = []
    if vol_count == 0:
        return volumes
    if vol_off <= 0 or vol_off + vol_size > len(data):
        notes.append(
            f"volume section [off=0x{vol_off:X} size={vol_size}] out of "
            "bounds; volume info unavailable")
        return volumes
    if vol_count > MAX_VOLUMES:
        notes.append(f"volume count {vol_count} capped at {MAX_VOLUMES}")
        vol_count = MAX_VOLUMES
    for i in range(vol_count):
        base = vol_off + i * entry_size
        try:
            dev_rel = _u32(data, base)
            nchars = _u32(data, base + 4)
            created = iso(filetime_to_utc(_u64(data, base + 8)))
            serial = f"0x{_u32(data, base + 16):08X}"
            dev_abs = vol_off + dev_rel
            raw = data[dev_abs:dev_abs + nchars * 2]
            if nchars == 0 or len(raw) < nchars * 2:
                raise PrefetchParseError("volume device path overruns section")
            device = raw.decode("utf-16-le", "replace").rstrip("\x00")
            dirs = _parse_dir_strings(
                data, vol_off, vol_size, _u32(data, base + 28),
                _u32(data, base + 32), notes, f"volume[{i}]")
        except PrefetchParseError as exc:
            notes.append(f"volume[{i}] parse error: {exc}")
            continue
        volumes.append({
            "device_path": device,
            "creation_time_utc": created,
            "serial_number": serial,
            "directories": dirs,
            "directory_count": len(dirs),
        })
    return volumes


def _run_count_offset(version, metrics_off):
    """File offset of the run-count DWORD for a given version/layout."""
    if version == 17:
        return 0x90
    if version == 23:
        return 0x98
    if version in (30, 31) and metrics_off == METRICS_OFF_V30_VARIANT2:
        return 0xC8  # v30 variant 2 / v31 layout
    return 0xD0  # v26, v30 variant 1


def parse_scca(data, source_path, machine_id=None):
    """Parse an uncompressed SCCA payload. Returns the artifact record dict."""
    data = bytes(data)
    if len(data) < 0x54:
        raise PrefetchParseError(f"file smaller than Prefetch header ({len(data)} bytes)")
    version = _u32(data, 0x00)
    if data[0x04:0x08] != SCCA_MAGIC:
        raise PrefetchParseError(
            f"missing SCCA signature (found {data[0x04:0x08]!r})")
    if version not in PF_VERSIONS:
        raise PrefetchParseError(f"unsupported Prefetch version {version}")

    notes = []
    parsers_used = ["builtin"]
    declared_size = _u32(data, 0x0C)
    if declared_size != len(data):
        notes.append(
            f"header file size {declared_size} != actual {len(data)} bytes")

    executable = data[0x10:0x4C].decode("utf-16-le", "replace").split("\x00", 1)[0].strip()
    if not executable:
        raise PrefetchParseError("empty executable name in header")
    prefetch_hash = _u32(data, 0x4C)

    # --- section table (offsets relative to start of file) -----------------
    metrics_off = _u32(data, 0x54)
    metrics_count = _u32(data, 0x58)
    fn_off = _u32(data, 0x64)
    fn_size = _u32(data, 0x68)
    vol_off = _u32(data, 0x6C)
    vol_count = _u32(data, 0x70)
    vol_size = _u32(data, 0x74)
    if metrics_count > 100000:
        notes.append(f"suspicious file-metrics count {metrics_count}")

    # --- execution timestamps (FILETIME slots, most-recent-first) ----------
    if version == 17:
        slot_offs = (0x78,)
    elif version == 23:
        slot_offs = (0x80,)
    else:
        slot_offs = tuple(0x80 + i * 8 for i in range(8))
    if slot_offs[-1] + 8 > len(data):
        raise PrefetchParseError("file truncated before execution timestamps")
    exec_times = []
    for raw in (_u64(data, off) for off in slot_offs):
        moment = filetime_to_utc(raw)
        if moment is None:
            if raw:
                notes.append(f"invalid execution timestamp 0x{raw:X}")
            continue
        exec_times.append(iso(moment))

    # --- run count ----------------------------------------------------------
    rc_off = _run_count_offset(version, metrics_off)
    if rc_off + 4 > len(data):
        raise PrefetchParseError("file truncated before run count")
    run_count = _u32(data, rc_off)
    if version in (30, 31):  # cross-check the sibling variant offset
        alt_off = 0xC8 if rc_off == 0xD0 else 0xD0
        try:
            alt = _u32(data, alt_off)
            if alt and not run_count:
                run_count = alt
                notes.append(
                    f"run count read from alternate offset 0x{alt_off:X} "
                    f"(layout heuristic picked 0x{rc_off:X})")
        except PrefetchParseError:
            pass

    referenced, truncated = _parse_filename_strings(data, fn_off, fn_size, notes)
    volumes = _parse_volumes(
        data, vol_off, vol_count, vol_size, VOLUME_ENTRY_SIZE[version], notes)

    # --- filename <-> header consistency -----------------------------------
    base = os.path.basename(source_path)
    stem = base[:-3] if base.lower().endswith(".pf") else base
    if "-" in stem:
        name_part, hash_part = stem.rsplit("-", 1)
        if len(hash_part) == 8:
            try:
                if int(hash_part, 16) != prefetch_hash:
                    notes.append(
                        f"filename hash 0x{hash_part.upper()} != header hash "
                        f"0x{prefetch_hash:08X}")
            except ValueError:
                pass
        if name_part.upper() != executable.upper() and not executable.upper().startswith(
                name_part.upper()[:29]):
            notes.append(
                f"filename executable {name_part!r} != header executable "
                f"{executable!r} (possible truncation/rename)")

    stat = os.stat(source_path)
    record = {
        "prefetch_file": base,
        "prefetch_path": os.path.abspath(source_path),
        "prefetch_file_size": len(data),
        "declared_file_size": declared_size,
        "executable_name": executable,
        "prefetch_hash": f"0x{prefetch_hash:08X}",
        "pf_version": version,
        "windows_version_hint": WINDOWS_HINT[version],
        "is_compressed_mam": False,  # flipped by parse_prefetch_file for MAM
        "run_count": run_count,
        "execution_times_utc": exec_times,
        "referenced_files": referenced,
        "referenced_files_count": len(referenced),
        "referenced_files_truncated": truncated,
        "directories_count": sum(v["directory_count"] for v in volumes),
        "volumes": volumes,
        "machine_id": machine_id,
        "parsers_used": parsers_used,
        "notes": notes,
    }
    record["pf_file_modified_utc"] = iso(
        dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc))
    record["pf_file_created_utc"] = (
        iso(dt.datetime.fromtimestamp(stat.st_birthtime, dt.timezone.utc))
        if hasattr(stat, "st_birthtime") else None)
    record["pf_file_accessed_utc"] = iso(
        dt.datetime.fromtimestamp(stat.st_atime, dt.timezone.utc))
    return record


def parse_prefetch_file(path, machine_id=None):
    """Parse one .pf file (MAM or SCCA). Returns the artifact record dict.

    Raises PrefetchParseError / MAMDecompressionError on invalid files.
    """
    size = os.path.getsize(path)
    if size > MAX_SANE_FILE:
        raise PrefetchParseError(f"file too large ({size} bytes)")
    if size == 0:
        raise PrefetchParseError("zero-byte file")
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 8:
        raise PrefetchParseError(f"file too small ({len(data)} bytes)")

    if data[:4] == MAM_MAGIC:
        expected = struct.unpack_from("<I", data, 4)[0]
        notes_extra = []
        parsers = ["builtin"]
        payload = data[8:]
        if not payload:
            raise MAMDecompressionError("MAM file has no compressed payload")
        raw = mam_decompress(payload, expected, notes_extra, parsers)
        if len(raw) != expected:
            notes_extra.append(
                f"MAM header uncompressed size {expected} != decompressed "
                f"{len(raw)} bytes")
        record = parse_scca(raw, path, machine_id=machine_id)
        record["is_compressed_mam"] = True
        record["parsers_used"] = parsers + [
            p for p in record["parsers_used"] if p not in parsers]
        record["notes"] = notes_extra + record["notes"]
        record["prefetch_file_size"] = size
        return record

    return parse_scca(data, path, machine_id=machine_id)


# --------------------------------------------------------------------------
# timeline construction (same event schema as lnk_forensics.make_events)
# --------------------------------------------------------------------------

def make_events(record):
    events = []
    times = record.get("execution_times_utc") or []
    for index, stamp in enumerate(times):
        events.append({
            "timestamp": stamp,
            "timestamp_type": "Last Execution" if index == 0 else f"Prior Execution #{index + 1}",
            "source": "Prefetch",
            "artifact_type": "prefetch",
            "prefetch_file": record["prefetch_file"],
            "prefetch_path": record["prefetch_path"],
            "prefetch_name": record["prefetch_file"],
            "artifact_name": record["prefetch_file"],
            "executable_name": record["executable_name"],
            "target_path": record["executable_name"],
            "details": {
                "executable_name": record["executable_name"],
                "prefetch_hash": record["prefetch_hash"],
                "run_count": record["run_count"],
                "run_index": index,
                "total_runs_recorded": len(times),
                "all_execution_times_utc": times,
                "pf_version": record["pf_version"],
                "windows_version_hint": record["windows_version_hint"],
                "file_size": record["prefetch_file_size"],
                "declared_file_size": record["declared_file_size"],
                "is_compressed_mam": record["is_compressed_mam"],
                "referenced_files": record["referenced_files"],
                "referenced_files_count": record["referenced_files_count"],
                "referenced_files_truncated": record["referenced_files_truncated"],
                "directories_count": record["directories_count"],
                "volumes": record["volumes"],
                "machine_id": record["machine_id"],
                "parsers_used": record["parsers_used"],
            },
        })
    for label, field in (
        ("Prefetch File Modified", "pf_file_modified_utc"),
        ("Prefetch File Created", "pf_file_created_utc"),
    ):
        stamp = record.get(field)
        if not stamp:
            continue
        events.append({
            "timestamp": stamp,
            "timestamp_type": label,
            "source": "Prefetch",
            "artifact_type": "prefetch",
            "prefetch_file": record["prefetch_file"],
            "prefetch_path": record["prefetch_path"],
            "prefetch_name": record["prefetch_file"],
            "artifact_name": record["prefetch_file"],
            "executable_name": record["executable_name"],
            "target_path": record["executable_name"],
            "details": {
                "executable_name": record["executable_name"],
                "prefetch_hash": record["prefetch_hash"],
                "run_count": record["run_count"],
                "run_index": None,
                "total_runs_recorded": len(times),
                "all_execution_times_utc": times,
                "pf_version": record["pf_version"],
                "windows_version_hint": record["windows_version_hint"],
                "file_size": record["prefetch_file_size"],
                "declared_file_size": record["declared_file_size"],
                "is_compressed_mam": record["is_compressed_mam"],
                "referenced_files": record["referenced_files"],
                "referenced_files_count": record["referenced_files_count"],
                "referenced_files_truncated": record["referenced_files_truncated"],
                "directories_count": record["directories_count"],
                "volumes": record["volumes"],
                "machine_id": record["machine_id"],
                "parsers_used": record["parsers_used"],
            },
        })
    return events


# --------------------------------------------------------------------------
# file discovery and CLI
# --------------------------------------------------------------------------

def iter_pf_files(root, recursive):
    if recursive:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames):
                if name.lower().endswith(".pf"):
                    yield os.path.join(dirpath, name)
    else:
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            if os.path.isfile(full) and name.lower().endswith(".pf"):
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
        description="Parse Windows Prefetch (.pf) files into a chronological "
                    "JSON timeline (same schema as lnk_forensics.py).")
    parser.add_argument("path", nargs="?", default=".",
                        help="directory with .pf files or a single .pf file "
                             "(default: current directory)")
    parser.add_argument("-o", "--output", default="prefetch_timeline.json",
                        help="output JSON file (default: prefetch_timeline.json)")
    parser.add_argument("--flat", action="store_true",
                        help="do not recurse into subdirectories (default: recursive)")
    parser.add_argument("--machine-id", default=None,
                        help="host identifier stamped into details.machine_id "
                             "(Prefetch stores none itself)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress the console summary table")
    args = parser.parse_args(argv)

    target = os.path.abspath(args.path)
    if os.path.isfile(target):
        candidates = [target] if target.lower().endswith(".pf") else []
        if not candidates:
            print(f"[!] not a .pf file: {target}", file=sys.stderr)
            return 2
        scan_root, recursive = os.path.dirname(target) or ".", False
    elif os.path.isdir(target):
        scan_root, recursive = target, not args.flat
        candidates = list(iter_pf_files(target, recursive=recursive))
    else:
        print(f"[!] no such file or directory: {target}", file=sys.stderr)
        return 2

    engine = ["builtin"]
    records, skipped, events = [], [], []
    for path in candidates:
        try:
            record = parse_prefetch_file(path, machine_id=args.machine_id)
        except Exception as exc:  # noqa: BLE001 - per-file resilience, mirrors LNK
            skipped.append({"file": os.path.abspath(path),
                            "error_type": type(exc).__name__,
                            "error": str(exc)})
            print(f"[!] skipped {path} ({type(exc).__name__}: {exc})", file=sys.stderr)
            continue
        for engine_tag in record["parsers_used"]:
            if engine_tag != "builtin" and engine_tag not in engine:
                engine.append(engine_tag)
        records.append(record)
        events.extend(make_events(record))

    events.sort(key=lambda e: (e["timestamp"], e["prefetch_path"], e["timestamp_type"]))

    versions = sorted({r["pf_version"] for r in records})
    machines = sorted({r["machine_id"] for r in records if r["machine_id"]})
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
                "pf_files_found": len(records) + len(skipped),
                "pf_files_parsed": len(records),
                "pf_files_failed": len(skipped),
                "timeline_events": len(events),
                "unique_executables": len({r["executable_name"] for r in records}),
                "versions_observed": versions,
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
        rows = [[i + 1, truncate(r["prefetch_file"], 30),
                 truncate(r["executable_name"], 22),
                 truncate(r["execution_times_utc"][0] if r["execution_times_utc"] else None, 26),
                 r["run_count"], r["pf_version"],
                 "MAM" if r["is_compressed_mam"] else "SCCA"]
                for i, r in enumerate(records)]
        print(f"\n[{TOOL}] {target} -> {out_path}")
        print(_plain_table(
            rows, ["#", "PF File", "Executable", "Last Execution (UTC)",
                   "Runs", "Ver", "Store"]) if rows else "(no parsed artifacts)")
        print()
        print(f"[+] {len(records)} Prefetch parsed, {len(skipped)} skipped, "
              f"{len(events)} timeline events -> {out_path}")
        if versions:
            print("[+] versions observed: " + ", ".join(str(v) for v in versions))
        if machines:
            print("[+] machines observed: " + ", ".join(machines))
        if skipped:
            print(f"[!] {len(skipped)} file(s) could not be parsed (see 'skipped' in JSON)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
