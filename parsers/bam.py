"""BAM (Background Activity Moderator) parser — SYSTEM hive execution times."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from parsers.base import ArtifactEvent, BaseParser


class BAMParser(BaseParser):
    artifact_type = "bam"
    display_name = "BAM"

    def parse(self, path: str | Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        bam_path = Path(path)

        if bam_path.suffix.lower() in (".json", ".txt", ".csv"):
            events = self._parse_export(bam_path)
        elif bam_path.is_dir():
            for f in bam_path.rglob("*"):
                if f.suffix.lower() in (".json", ".txt", ".csv"):
                    events.extend(self._parse_export(f))
        return events

    def _parse_export(self, path: Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return events

        for line in text.splitlines():
            parts = line.strip().split("|")
            if len(parts) >= 2:
                user_sid = parts[0].strip()
                last_run = parts[1].strip() if len(parts) > 1 else ""
                dt = None
                ts_str = last_run
                if last_run:
                    try:
                        dt = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
                        ts_str = dt.isoformat()
                    except ValueError:
                        try:
                            dt = datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S")
                            dt = dt.replace(tzinfo=timezone.utc)
                            ts_str = dt.isoformat()
                        except ValueError:
                            pass

                events.append(ArtifactEvent(
                    timestamp=ts_str, dt=dt, source="BAM",
                    event_type="BAM Last Run",
                    artifact_name=f"BAM-{user_sid}",
                    target_path=f"BAM-{user_sid}",
                    machine_id=user_sid,
                    details={"user_sid": user_sid},
                ))
        return events
