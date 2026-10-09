"""Shellbag parser — NTUSER.DAT folder access tracking."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from parsers.base import ArtifactEvent, BaseParser


class ShellbagParser(BaseParser):
    artifact_type = "shellbag"
    display_name = "Shellbags"

    def parse(self, path: str | Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        sb_path = Path(path)

        if sb_path.suffix.lower() in (".json", ".txt", ".csv"):
            events = self._parse_export(sb_path)
        elif sb_path.is_dir():
            for f in sb_path.rglob("*"):
                if f.suffix.lower() in (".json", ".txt", ".csv"):
                    events.extend(self._parse_export(f))
        return events

    def _parse_export(self, path: Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        try:
            import json
            if path.suffix.lower() == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
                entries = data if isinstance(data, list) else data.get("entries", [])
            else:
                text = path.read_text(encoding="utf-8", errors="replace")
                entries = []
                for line in text.splitlines():
                    parts = line.strip().split("|")
                    if len(parts) >= 1:
                        entry = {"path": parts[0].strip()}
                        if len(parts) > 1:
                            entry["mtime"] = parts[1].strip()
                        if len(parts) > 2:
                            entry["deleted"] = parts[2].strip().lower() in ("true", "1", "yes")
                        if len(parts) > 3:
                            entry["renamed"] = parts[3].strip().lower() in ("true", "1", "yes")
                        entries.append(entry)
        except (OSError, ValueError):
            return events

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            folder_path = entry.get("path", entry.get("name", "Unknown"))
            mtime_str = entry.get("mtime", entry.get("modified", ""))
            dt = None
            ts_str = mtime_str
            if mtime_str:
                try:
                    dt = datetime.fromisoformat(mtime_str.replace("Z", "+00:00"))
                    ts_str = dt.isoformat()
                except ValueError:
                    try:
                        dt = datetime.strptime(mtime_str, "%Y-%m-%d %H:%M:%S")
                        dt = dt.replace(tzinfo=timezone.utc)
                        ts_str = dt.isoformat()
                    except ValueError:
                        pass

            name = Path(str(folder_path)).name if folder_path else "Unknown"
            events.append(ArtifactEvent(
                timestamp=ts_str, dt=dt, source="Shellbag",
                event_type="Shellbag Access",
                artifact_name=name, target_path=str(folder_path),
                machine_id="N/A",
                details={
                    "deleted": bool(entry.get("deleted", False)),
                    "renamed": bool(entry.get("renamed", False)),
                    "size": entry.get("size", ""),
                },
            ))
        return events
