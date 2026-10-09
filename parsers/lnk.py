"""LNK shortcut parser — extracts target paths from Windows .lnk files."""

from __future__ import annotations

from pathlib import Path

from parsers.base import ArtifactEvent, BaseParser


class LNKParser(BaseParser):
    artifact_type = "lnk"
    display_name = "LNK"

    def parse(self, path: str | Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        lnk_path = Path(path)
        if lnk_path.is_dir():
            files = list(lnk_path.rglob("*.lnk"))
        else:
            files = [lnk_path]

        for lf in files:
            try:
                data = lf.read_bytes()
            except OSError:
                continue
            if len(data) < 0x4C:
                continue
            import struct
            if struct.unpack_from("<I", data, 0)[0] != 0x4C:
                continue
            target = self._extract_target(data)
            try:
                import datetime
                mtime = datetime.datetime.fromtimestamp(
                    lf.stat().st_mtime, tz=datetime.timezone.utc)
                ts_str, dt = mtime.isoformat(), mtime
            except OSError:
                ts_str, dt = "", None

            events.append(ArtifactEvent(
                timestamp=ts_str,
                dt=dt,
                source="LNK",
                event_type="LNK Shortcut",
                artifact_name=lf.name,
                target_path=target or lf.name,
                machine_id="N/A",
                details={"file_size": len(data)},
            ))
        return events

    @staticmethod
    def _extract_target(data: bytes) -> str:
        try:
            offset = 0x4C
            while offset < len(data) - 1:
                end = data.find(b"\x00\x00", offset)
                if end == -1:
                    break
                chunk = data[offset:end]
                decoded = chunk.decode("utf-8", errors="replace").rstrip("\x00")
                if "\\" in decoded or ":" in decoded:
                    return decoded
                offset = end + 2
        except (OSError, UnicodeDecodeError):
            pass
        return ""
