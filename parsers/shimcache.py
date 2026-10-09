"""ShimCache (AppCompatCache) parser — SYSTEM registry execution evidence."""

from __future__ import annotations

import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path

from parsers.base import ArtifactEvent, BaseParser


class ShimCacheParser(BaseParser):
    artifact_type = "shimcache"
    display_name = "ShimCache"

    def parse(self, path: str | Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        sc_path = Path(path)

        if sc_path.suffix.lower() in (".json", ".txt", ".csv"):
            events = self._parse_export(sc_path)
        elif sc_path.suffix.lower() == ".bin" or sc_path.is_file():
            events = self._parse_binary(sc_path)
        elif sc_path.is_dir():
            for f in sc_path.rglob("*"):
                if f.suffix.lower() in (".json", ".txt", ".csv", ".bin"):
                    if f.suffix.lower() == ".bin":
                        events.extend(self._parse_binary(f))
                    else:
                        events.extend(self._parse_export(f))
        return events

    def _parse_binary(self, path: Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        try:
            data = path.read_bytes()
        except OSError:
            return events

        offset = 0
        while offset < len(data) - 4:
            try:
                entry_len = struct.unpack_from("<I", data, offset)[0]
                if 8 < entry_len < 4096 and offset + 4 + entry_len <= len(data):
                    entry = data[offset + 4:offset + 4 + entry_len]
                    path_str = entry.decode("utf-16-le", errors="replace").rstrip("\x00")
                    if "\\" in path_str:
                        events.append(ArtifactEvent(
                            timestamp="", dt=None, source="ShimCache",
                            event_type="ShimCache Entry",
                            artifact_name=Path(path_str).name if "\\" in path_str else path_str,
                            target_path=path_str,
                            machine_id="N/A",
                            details={"entry_size": entry_len},
                        ))
                        offset += 4 + entry_len
                        continue
            except (struct.error, IndexError):
                pass
            offset += 1
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
                    if len(parts) >= 1:
                        entry = {"path": parts[0].strip()}
                        if len(parts) > 1:
                            entry["last_modified"] = parts[1].strip()
                        entries.append(entry)
        except (OSError, ValueError):
            return events

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            file_path = entry.get("path", entry.get("name", "Unknown"))
            lm = entry.get("last_modified", entry.get("mtime", ""))
            dt = None
            ts_str = lm
            if lm:
                try:
                    dt = datetime.fromisoformat(lm.replace("Z", "+00:00"))
                    ts_str = dt.isoformat()
                except ValueError:
                    try:
                        dt = datetime.strptime(lm, "%Y-%m-%d %H:%M:%S")
                        dt = dt.replace(tzinfo=timezone.utc)
                        ts_str = dt.isoformat()
                    except ValueError:
                        pass

            name = Path(str(file_path)).name if file_path else "Unknown"
            events.append(ArtifactEvent(
                timestamp=ts_str, dt=dt, source="ShimCache",
                event_type="ShimCache Entry",
                artifact_name=name, target_path=str(file_path),
                machine_id="N/A",
                details={},
            ))
        return events
