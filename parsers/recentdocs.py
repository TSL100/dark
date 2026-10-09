"""RecentDocs parser — NTUSER.DAT recently accessed document tracking."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from parsers.base import ArtifactEvent, BaseParser


class RecentDocsParser(BaseParser):
    artifact_type = "recentdocs"
    display_name = "RecentDocs"

    def parse(self, path: str | Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        rd_path = Path(path)

        if rd_path.suffix.lower() in (".json", ".txt", ".csv"):
            events = self._parse_export(rd_path)
        elif rd_path.is_dir():
            for f in rd_path.rglob("*"):
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
                entries = []
                text = path.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    parts = line.strip().split("|")
                    if len(parts) >= 1:
                        entry = {"path": parts[0].strip()}
                        if len(parts) > 1:
                            entry["last_accessed"] = parts[1].strip()
                        entries.append(entry)
        except (OSError, ValueError):
            return events

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            doc_path = entry.get("path", entry.get("name", "Unknown"))
            accessed = entry.get("last_accessed", entry.get("mtime", ""))
            dt = None
            ts_str = accessed
            if accessed:
                try:
                    dt = datetime.fromisoformat(accessed.replace("Z", "+00:00"))
                    ts_str = dt.isoformat()
                except ValueError:
                    try:
                        dt = datetime.strptime(accessed, "%Y-%m-%d %H:%M:%S")
                        dt = dt.replace(tzinfo=timezone.utc)
                        ts_str = dt.isoformat()
                    except ValueError:
                        pass

            name = Path(str(doc_path)).name if doc_path else "Unknown"
            events.append(ArtifactEvent(
                timestamp=ts_str, dt=dt, source="RecentDocs",
                event_type="RecentDoc Access",
                artifact_name=name, target_path=str(doc_path),
                machine_id="N/A",
                details={},
            ))
        return events
