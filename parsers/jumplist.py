"""JumpList parser — processes automatic and custom jump list files."""

from __future__ import annotations

import struct
from pathlib import Path

from parsers.base import ArtifactEvent, BaseParser


class JumpListParser(BaseParser):
    artifact_type = "jumplist"
    display_name = "JumpLists"

    def parse(self, path: str | Path) -> list[ArtifactEvent]:
        events: list[ArtifactEvent] = []
        jl_path = Path(path)
        if jl_path.is_dir():
            patterns = ["*.automaticDestinations-ms", "*.customDestinations-ms"]
            files: list[Path] = []
            for p in patterns:
                files.extend(jl_path.rglob(p))
        else:
            files = [jl_path]

        for jf in files:
            try:
                data = jf.read_bytes()
            except OSError:
                continue
            targets = self._extract_targets(data)
            try:
                import datetime
                mtime = datetime.datetime.fromtimestamp(
                    jf.stat().st_mtime, tz=datetime.timezone.utc)
                ts_str, dt = mtime.isoformat(), mtime
            except OSError:
                ts_str, dt = "", None

            if not targets:
                events.append(ArtifactEvent(
                    timestamp=ts_str, dt=dt, source="JumpLists",
                    event_type="JumpList Modified",
                    artifact_name=jf.name, target_path=jf.name,
                    machine_id="N/A", details={},
                ))
            else:
                for target in targets:
                    events.append(ArtifactEvent(
                        timestamp=ts_str, dt=dt, source="JumpLists",
                        event_type="JumpList Target",
                        artifact_name=jf.name, target_path=target,
                        machine_id="N/A", details={},
                    ))
        return events

    @staticmethod
    def _extract_targets(data: bytes) -> list[str]:
        targets: list[str] = []
        offset = 0
        while offset < len(data) - 8:
            try:
                if data[offset:offset + 4] == b"\x03\x00\x00\x00":
                    length = struct.unpack_from("<I", data, offset + 4)[0]
                    if 4 < length < 4096 and offset + 8 + length <= len(data):
                        chunk = data[offset + 8:offset + 8 + length]
                        decoded = chunk.decode("utf-16-le", errors="replace").rstrip("\x00")
                        if "\\" in decoded or ":" in decoded:
                            targets.append(decoded)
                            offset += 8 + length
                            continue
            except (struct.error, IndexError):
                pass
            offset += 1
        return targets[:50]
