"""Prefetch (*.pf) parser — extracts execution timestamps and run counts."""

from __future__ import annotations

import struct
from pathlib import Path

from parsers.base import ArtifactEvent, BaseParser, parse_timestamp


class PrefetchParser(BaseParser):
    artifact_type = "prefetch"
    display_name = "Prefetch"

    def parse(self, path: str | Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        pf_path = Path(path)
        if pf_path.is_dir():
            files = sorted(pf_path.glob("*.pf"))
        else:
            files = [pf_path]

        for pf in files:
            try:
                data = pf.read_bytes()
            except OSError:
                continue
            if len(data) < 8:
                continue
            version = struct.unpack_from("<I", data, 0)[0]
            name = self._read_name(data, version) or pf.stem
            run_count = 0
            if len(data) >= 0x84:
                run_count = struct.unpack_from("<I", data, 0x80)[0]

            for i in range(min(run_count, 20)):
                ts_raw = self._read_ts(data, version, i)
                if ts_raw is None or ts_raw == 0:
                    continue
                ts_str, dt = self._ts_from_filetime(ts_raw)
                events.append(ArtifactEvent(
                    timestamp=ts_str,
                    dt=dt,
                    source="Prefetch",
                    event_type="Prefetch Execution",
                    artifact_name=name,
                    target_path=name,
                    machine_id="N/A",
                    details={"run_count": run_count, "run_index": i,
                             "pf_file": pf.name},
                ))
        return events

    @staticmethod
    def _read_name(data: bytes, version: int) -> str:
        try:
            if version == 0x11:
                offset, length = 0x54, struct.unpack_from("<I", data, 0x50)[0] * 2
            elif version in (0x17, 0x1A):
                offset, length = 0x64, struct.unpack_from("<I", data, 0x60)[0] * 2
            else:
                return ""
            end = min(offset + length, len(data))
            return data[offset:end].decode("utf-16-le", errors="replace").rstrip("\x00")
        except (struct.error, IndexError):
            return ""

    @staticmethod
    def _read_ts(data: bytes, version: int, index: int) -> int | None:
        base = {"0x11": 0x98, "0x17": 0xD0, "0x1A": 0xD0}
        off = {0x11: 0x98, 0x17: 0xD0, 0x1A: 0xD0}.get(version, 0x98)
        try:
            return struct.unpack_from("<Q", data, off + index * 8)[0]
        except struct.error:
            return None

    @staticmethod
    def _ts_from_filetime(raw: int) -> tuple[str, object]:
        from datetime import datetime, timezone, timedelta
        try:
            dt = datetime(1601, 1, 1) + timedelta(microseconds=raw / 10)
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat(), dt
        except (OverflowError, OSError):
            return str(raw), None
