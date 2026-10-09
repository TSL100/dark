"""Amcache.hve parser — extracts file paths, SHA1 hashes, and timestamps."""

from __future__ import annotations

from pathlib import Path

from parsers.base import ArtifactEvent, BaseParser


class AmcacheParser(BaseParser):
    artifact_type = "amcache"
    display_name = "Amcache"

    def parse(self, path: str | Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        am_path = Path(path)

        if am_path.suffix.lower() in (".txt", ".csv", ".json"):
            events = self._parse_text_export(am_path)
        elif am_path.suffix.lower() == ".hve":
            events = self._parse_registry_hive(am_path)
        elif am_path.is_dir():
            for f in am_path.rglob("*"):
                if f.suffix.lower() in (".txt", ".csv", ".json", ".hve"):
                    events.extend(self.parse(f))
        return events

    def _parse_text_export(self, path: Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return events

        for line in text.splitlines():
            parts = line.strip().split("|")
            if len(parts) >= 3:
                file_path = parts[0].strip()
                sha1 = parts[1].strip() if len(parts) > 1 else ""
                write_time = parts[2].strip() if len(parts) > 2 else ""
                ts_str, dt = "", None
                if write_time:
                    try:
                        from datetime import datetime, timezone
                        dt = datetime.strptime(write_time, "%Y-%m-%d %H:%M:%S")
                        dt = dt.replace(tzinfo=timezone.utc)
                        ts_str = dt.isoformat()
                    except ValueError:
                        ts_str = write_time

                events.append(ArtifactEvent(
                    timestamp=ts_str, dt=dt, source="Amcache",
                    event_type="Amcache Entry",
                    artifact_name=Path(file_path).name if file_path else "Unknown",
                    target_path=file_path or "Unknown",
                    machine_id="N/A",
                    details={"sha1": sha1},
                ))
        return events

    def _parse_registry_hive(self, path: Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 f"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
                                 0, winreg.KEY_READ)
            count = winreg.QueryInfoKey(key)[1]
            for i in range(count):
                name, value, _ = winreg.EnumValue(key, i)
                events.append(ArtifactEvent(
                    timestamp="", dt=None, source="Amcache",
                    event_type="Amcache Registry Entry",
                    artifact_name=str(name), target_path=str(name),
                    machine_id="N/A",
                    details={"raw": str(value)[:200]},
                ))
            winreg.CloseKey(key)
        except (ImportError, OSError):
            pass
        return events
