"""Base classes and unified schema for all DFIR artifact parsers."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "1.0"


@dataclass
class ArtifactEvent:
    """Unified event schema shared by every parser."""

    timestamp: str
    dt: Optional[datetime]
    source: str
    event_type: str
    artifact_name: str
    target_path: str
    machine_id: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "artifact_name": self.artifact_name,
            "target_path": self.target_path,
            "machine_id": self.machine_id,
            "details": self.details,
        }


class BaseParser(ABC):
    """Abstract base for every artifact parser.

    Subclasses must set ``artifact_type`` and implement ``parse``.
    """

    artifact_type: str = "unknown"
    display_name: str = "Unknown"

    @abstractmethod
    def parse(self, path: str | Path) -> list[ArtifactEvent]:
        """Parse one artifact file/directory and return events."""

    def to_json(self, events: list[ArtifactEvent], source_path: str) -> str:
        """Serialise events to the unified JSON document."""
        doc = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": self.artifact_type,
            "source_path": str(source_path),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "event_count": len(events),
            "events": [ev.to_json_dict() for ev in events],
        }
        return json.dumps(doc, indent=2, ensure_ascii=False)

    def parse_and_save(self, path: str | Path, out_path: str | Path) -> int:
        events = self.parse(path)
        Path(out_path).write_text(
            self.to_json(events, str(path)), encoding="utf-8")
        return len(events)


def parse_timestamp(value: Any) -> tuple[str, Optional[datetime]]:
    """Best-effort timestamp parsing from raw artifact data."""
    if isinstance(value, (int, float)) and value > 0:
        try:
            moment = datetime.fromtimestamp(value, tz=timezone.utc)
            return moment.isoformat(), moment
        except (OverflowError, OSError, ValueError):
            return str(value), None
    text = str(value).strip() if value is not None else ""
    if not text:
        return "", None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text, None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return text, moment
