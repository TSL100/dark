"""Recycle Bin parser — $I/$R file pair analysis for deleted file recovery."""

from __future__ import annotations

import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path

from parsers.base import ArtifactEvent, BaseParser


class RecycleBinParser(BaseParser):
    artifact_type = "recyclebin"
    display_name = "RecycleBin"

    def parse(self, path: str | Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        rb_path = Path(path)

        if rb_path.is_dir():
            for i_file in rb_path.rglob("$I*"):
                events.extend(self._parse_i_file(i_file))
            for r_file in rb_path.rglob("$R*"):
                events.extend(self._parse_r_file(r_file))
        elif rb_path.name.startswith("$I"):
            events.extend(self._parse_i_file(rb_path))
        elif rb_path.name.startswith("$R"):
            events.extend(self._parse_r_file(rb_path))
        elif rb_path.suffix.lower() in (".json", ".txt"):
            events = self._parse_export(rb_path)
        return events

    def _parse_i_file(self, path: Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        try:
            data = path.read_bytes()
        except OSError:
            return events

        if len(data) < 28:
            return events

        try:
            version = struct.unpack_from("<Q", data, 0)[0]
            if version == 2:
                orig_size = struct.unpack_from("<Q", data, 8)[0]
                ts_raw = struct.unpack_from("<Q", data, 16)[0]
                name_len = struct.unpack_from("<I", data, 24)[0]
                name_offset = 28
            else:
                orig_size = struct.unpack_from("<I", data, 8)[0]
                ts_raw = struct.unpack_from("<I", data, 12)[0]
                name_offset = 20
                name_len = len(data) - name_offset

            ts_str, dt = "", None
            if ts_raw > 0:
                try:
                    dt = datetime(1601, 1, 1) + timedelta(microseconds=ts_raw / 10)
                    dt = dt.replace(tzinfo=timezone.utc)
                    ts_str = dt.isoformat()
                except (OverflowError, OSError):
                    pass

            name = ""
            try:
                raw_name = data[name_offset:name_offset + min(name_len, 512)]
                encoding = "utf-16-le" if version == 2 else "utf-8"
                name = raw_name.decode(encoding, errors="replace").rstrip("\x00")
            except (UnicodeDecodeError, IndexError):
                name = path.stem

            events.append(ArtifactEvent(
                timestamp=ts_str, dt=dt, source="RecycleBin",
                event_type="Deleted File",
                artifact_name=name, target_path=name,
                machine_id="N/A",
                details={"orig_size": orig_size, "i_file": path.name},
            ))
        except (struct.error, IndexError):
            pass
        return events

    def _parse_r_file(self, path: Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        try:
            stat = path.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            events.append(ArtifactEvent(
                timestamp=mtime.isoformat(), dt=mtime, source="RecycleBin",
                event_type="Recycle Bin Content",
                artifact_name=path.name, target_path=str(path),
                machine_id="N/A",
                details={"file_size": stat.st_size},
            ))
        except OSError:
            pass
        return events

    def _parse_export(self, path: Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        try:
            import json
            if path.suffix.lower() == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
                entries = data if isinstance(data, list) else data.get("entries", [])
            else:
                entries = []
                text = path.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    parts = line.strip().split("|")
                    if len(parts) >= 2:
                        entries.append({
                            "name": parts[0].strip(),
                            "deletion_time": parts[1].strip(),
                            "orig_path": parts[2].strip() if len(parts) > 2 else "",
                        })
        except (OSError, ValueError):
            return events

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "Unknown")
            del_time = entry.get("deletion_time", "")
            dt = None
            ts_str = del_time
            if del_time:
                try:
                    dt = datetime.fromisoformat(del_time.replace("Z", "+00:00"))
                    ts_str = dt.isoformat()
                except ValueError:
                    pass

            events.append(ArtifactEvent(
                timestamp=ts_str, dt=dt, source="RecycleBin",
                event_type="Deleted File",
                artifact_name=str(name),
                target_path=str(entry.get("orig_path", name)),
                machine_id="N/A",
                details={},
            ))
        return events
