"""UserAssist parser — tracks GUI application executions from NTUSER.DAT."""

from __future__ import annotations

import base64
import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path

from parsers.base import ArtifactEvent, BaseParser


class UserAssistParser(BaseParser):
    artifact_type = "userassist"
    display_name = "UserAssist"

    def parse(self, path: str | Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        ua_path = Path(path)

        if ua_path.suffix.lower() == ".json":
            events = self._parse_json(ua_path)
        elif ua_path.suffix.lower() in (".txt", ".csv"):
            events = self._parse_text(ua_path)
        elif ua_path.is_dir():
            for f in ua_path.rglob("*"):
                if f.suffix.lower() in (".json", ".txt", ".csv"):
                    events.extend(self.parse(f))
        return events

    def _parse_json(self, path: Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        try:
            import json
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return events

        entries = data if isinstance(data, list) else data.get("entries", [])
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", entry.get("path", "Unknown"))
            run_count = entry.get("run_count", 0)
            last_exec = entry.get("last_execution", entry.get("last_run", ""))
            ts_str, dt = "", None
            if isinstance(last_exec, (int, float)) and last_exec > 0:
                try:
                    dt = datetime(1601, 1, 1) + timedelta(microseconds=last_exec / 10)
                    dt = dt.replace(tzinfo=timezone.utc)
                    ts_str = dt.isoformat()
                except (OverflowError, OSError):
                    pass
            elif last_exec:
                ts_str = str(last_exec)
                try:
                    dt = datetime.fromisoformat(str(last_exec).replace("Z", "+00:00"))
                except ValueError:
                    pass

            events.append(ArtifactEvent(
                timestamp=ts_str, dt=dt, source="UserAssist",
                event_type="UserAssist Execution",
                artifact_name=str(name), target_path=str(name),
                machine_id="N/A",
                details={"run_count": run_count},
            ))
        return events

    def _parse_text(self, path: Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return events
        for line in text.splitlines():
            parts = line.strip().split("|")
            if len(parts) >= 2:
                name = parts[0].strip()
                run_count = 0
                last_run = parts[1].strip() if len(parts) > 1 else ""
                if len(parts) > 2:
                    try:
                        run_count = int(parts[2].strip())
                    except ValueError:
                        pass
                ts_str, dt = "", None
                if last_run:
                    try:
                        dt = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
                        ts_str = dt.isoformat()
                    except ValueError:
                        ts_str = last_run

                events.append(ArtifactEvent(
                    timestamp=ts_str, dt=dt, source="UserAssist",
                    event_type="UserAssist Execution",
                    artifact_name=name, target_path=name,
                    machine_id="N/A",
                    details={"run_count": run_count},
                ))
        return events
