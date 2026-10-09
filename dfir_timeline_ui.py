#!/usr/bin/env python3
"""DFIR Timeline Analyzer — enterprise-grade PySide6 UI for forensic artifact timelines.

Features:
    - Multi-file merging with chronological sort
    - Time-range filtering (attack window isolation)
    - Regex and substring search
    - CSV / HTML report export with SHA-256 chain-of-custody hashes
    - Scalable graph visualization (zoom, pan, no arbitrary truncation)
    - Color-coded artifact sources for rapid visual triage
    - Cloud AI forensic storytelling (OpenAI-compatible API)
    - On-the-fly threat detection engine (Sigma/YARA-lite rules)
    - Reverse execution trace ("Trace Origin") for root cause analysis
    - Comprehensive forensic artifact ingestion (Prefetch, Amcache, UserAssist, BAM, LNK, JumpLists, ShellBags, RecentDocs, Recycle Bin)
    - Granular artifact sub-views with ingestion toggles
    - Shellbags Explorer with cleanup tracking (deleted/moved/renamed items)

Usage:
    python dfir_timeline_ui.py [timeline.json ...]
"""

from __future__ import annotations

import csv
import hashlib
import html
import json
import math
import re
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

try:
    from tier1_artifacts import TIER1 as TIER1_ARTIFACTS
    _TIER1_AVAILABLE = True
except ImportError:  # acquisition panel degrades to an explanatory note
    TIER1_ARTIFACTS = []
    _TIER1_AVAILABLE = False

from PySide6.QtCore import (
    QPointF,
    QDateTime,
    QRectF,
    QSize,
    Qt,
    QThread,
    QSettings,
    QTimer,
    Signal,
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QKeySequence,
    QPalette,
    QPen,
    QPolygonF,
    QAction,
    QMouseEvent,
    QPainter,
    QPainterPath,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGraphicsPathItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QScrollArea,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

APP_NAME = "DFIR Timeline Analyzer"

STAGE_COLORS = {
    "machine": "#3fb950",
    "artifact": "#58a6ff",
    "target": "#d29922",
}

ARTIFACT_COLORS = {
    "LNK": "#f0883e",
    "Prefetch": "#58a6ff",
    "JumpLists": "#39c5cf",
    "Shellbag": "#a371f7",
    "Amcache": "#f778ba",
    "SRUM": "#7ee787",
    "UserAssist": "#e3b341",
    "BAM": "#ff9b72",
    "RecentDocs": "#79c0ff",
    "RecycleBin": "#f85149",
    "RegistryMRU": "#76e3ea",
    "USB": "#d2a8ff",
    "PowerShell": "#8b949e",
    "ZoneIdentifier": "#ffdf5d",
    "Shimcache": "#dbb8f0",
    "Unknown": "#8a8a8a",
}

THREAT_COLORS = {
    "high": "#f85149",
    "medium": "#d29922",
    "low": "#8a8a8a",
}

STAGE_TITLES = {
    "machine": "Machine ID",
    "target": "Target Path",
}

ARTIFACT_TITLES = {
    "LNK": "LNK File",
    "Prefetch": "Prefetch File",
    "JumpLists": "Jump List File",
    "Shellbag": "Shellbag Key",
    "Amcache": "Amcache Entry",
    "SRUM": "SRUM Record",
    "UserAssist": "UserAssist Entry",
    "BAM": "BAM Entry",
    "RecentDocs": "RecentDocs Entry",
    "RecycleBin": "RecycleBin Entry",
    "RegistryMRU": "Registry MRU Entry",
    "USB": "USB History Entry",
    "PowerShell": "PowerShell History Entry",
    "ZoneIdentifier": "Zone.Identifier Entry",
    "Shimcache": "Shimcache Entry",
}

EVENT_ALIASES = {
    "Target Creation": "Target Created",
    "Target Access": "Target Accessed",
    "Target Modification": "Target Modified",
    "LNK File Created": "LNK File Created",
    "LNK File Modified": "LNK File Modified",
}

NODE_W = 300
NODE_H = 72
COL_GAP = 120
ROW_GAP = 36
MARGIN = 40
CAPTION_Y = -30
CHAINS_PER_PAGE = 200
CARD_W = 300
CARD_H = 118
CARD_GAP = 16
SECTION_GAP = 30
HEATMAP_BINS = 120

DARK_QSS = """
QWidget { color: #e0e0e0; }
QMainWindow, QDialog { background: #121212; }
QToolTip {
    background: #1e1e1e; color: #d4d4d4;
    border: 1px solid #3c3c3c; padding: 4px 6px;
}
QPushButton {
    background: #2d2d2d; border: 1px solid #3c3c3c; border-radius: 4px;
    padding: 7px 14px; min-height: 20px;
}
QPushButton:hover { background: #3e3e42; border-color: #5a5a5a; }
QPushButton:pressed { background: #0969da; border-color: #0969da; color: #ffffff; }
QPushButton:disabled { background: #1e1e1e; color: #6d6d6d; border-color: #333333; }
QPushButton#primaryButton {
    background: #0969da; border-color: #58a6ff; color: #ffffff; font-weight: 600;
}
QPushButton#primaryButton:hover { background: #1177bb; }
QPushButton#primaryButton:pressed { background: #0c5a8f; }
QToolButton#regexToggle {
    background: #2d2d2d; border: 1px solid #3c3c3c; border-radius: 4px;
    padding: 7px 10px; min-height: 20px; font-weight: 700; color: #8a8a8a;
}
QToolButton#regexToggle:checked {
    background: #0e3a3a; border-color: #22d3ee; color: #22d3ee;
}
QPushButton#threatToggle {
    background: #2d2d2d; border: 1px solid #3c3c3c; border-radius: 4px;
    padding: 7px 10px; min-height: 20px; font-weight: 600; color: #8a8a8a;
}
QPushButton#threatToggle:checked {
    background: #5c1a1a; border-color: #f85149; color: #f85149;
}
QLineEdit, QTreeWidget, QTableWidget {
    background: #1e1e1e; border: 1px solid #3c3c3c;
    selection-background-color: #0969da; selection-color: #ffffff;
}
QLineEdit {
    border-radius: 4px; padding: 7px 9px; min-height: 20px;
    placeholder-text-color: #7a7a7a;
}
QLineEdit:focus { border-color: #22d3ee; }
QLineEdit#searchInvalid { border: 1px solid #f85149; }
QComboBox {
    background: #1e1e1e; border: 1px solid #3c3c3c;
    border-radius: 4px; padding: 6px 9px; min-height: 22px;
    selection-background-color: #0969da; selection-color: #ffffff;
}
QComboBox:focus { border-color: #22d3ee; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView {
    background: #1e1e1e; border: 1px solid #3c3c3c;
    selection-background-color: #0969da; selection-color: #ffffff;
    outline: none;
}
QDateTimeEdit {
    background: #1e1e1e; border: 1px solid #3c3c3c;
    border-radius: 4px; padding: 7px 9px; min-height: 22px;
}
QDateTimeEdit:focus { border-color: #22d3ee; }
QDateTimeEdit::drop-down { border: none; width: 22px; }
QCheckBox { spacing: 6px; }
QCheckBox::indicator {
    width: 16px; height: 16px; border-radius: 3px;
    border: 1px solid #3c3c3c; background: #1e1e1e;
}
QCheckBox::indicator:checked {
    background: #0969da; border-color: #58a6ff;
}
QLabel { background: transparent; }
QLabel#pathLabel {
    color: #9d9d9d; background: #1e1e1e; border: 1px solid #3c3c3c;
    border-radius: 4px; padding: 7px 9px;
}
QLabel#mutedLabel { color: #9a9a9a; font-size: 9pt; }
QLabel#heatmapCaption { color: #9a9a9a; font-size: 8pt; }
QLabel#panelTitle { color: #ffffff; font-size: 11pt; font-weight: 600; }
QTabWidget::pane {
    border: 1px solid #3c3c3c; background: #121212; top: -1px;
}
QTabBar::tab {
    background: #1e1e1e; color: #9d9d9d;
    padding: 8px 18px; margin-right: 2px;
    border: 1px solid #3c3c3c; border-bottom: none;
    border-top-left-radius: 4px; border-top-right-radius: 4px;
}
QTabBar::tab:selected { background: #121212; color: #ffffff; font-weight: 600; }
QTabBar::tab:hover:!selected { background: #2d2d2d; color: #d4d4d4; }
QHeaderView::section {
    background: #2d2d2d; color: #cccccc;
    border: none; border-right: 1px solid #3c3c3c; border-bottom: 1px solid #3c3c3c;
    padding: 6px 8px; font-weight: 600;
}
QHeaderView::section:hover { background: #3e3e42; }
QTableWidget {
    border: none; gridline-color: #3c3c3c;
    alternate-background-color: #1a1a1a;
}
QTableWidget::item { padding: 3px 4px; }
QTableWidget::item:selected { background: #0969da; color: #ffffff; }
QTreeWidget { border: none; alternate-background-color: #1a1a1a; }
QTreeWidget::item { height: 22px; padding: 1px 3px; }
QTreeWidget::item:selected { background: #0969da; color: #ffffff; }
QTreeWidget::branch { background: #1e1e1e; }
QSplitter::handle { background: #121212; }
QSplitter::handle:horizontal { width: 6px; }
QSplitter::handle:vertical { height: 6px; }
QSplitter::handle:hover { background: #0969da; }
QStatusBar {
    background: #121212; color: #9d9d9d;
    border-top: 1px solid #3c3c3c;
}
QStatusBar::item { border: none; }
QGraphicsView {
    border: none; background: #121212;
}
QScrollBar:vertical {
    background: #121212; width: 12px; margin: 0;
}
QScrollBar::handle:vertical {
    background: #424248; min-height: 30px; border-radius: 5px;
}
QScrollBar::handle:vertical:hover { background: #5a5a60; }
QScrollBar:horizontal {
    background: #121212; height: 12px; margin: 0;
}
QScrollBar::handle:horizontal {
    background: #424248; min-width: 30px; border-radius: 5px;
}
QScrollBar::handle:horizontal:hover { background: #5a5a60; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QScrollBar::corner { background: #121212; }
QTextEdit {
    background: #1e1e1e; border: 1px solid #3c3c3c;
    border-radius: 4px; padding: 8px;
}
"""


def dark_palette() -> QPalette:
    pal = QPalette()

    def setc(role: QPalette.ColorRole, value: str) -> None:
        pal.setColor(role, QColor(value))

    setc(QPalette.ColorRole.Window, "#121212")
    setc(QPalette.ColorRole.WindowText, "#e0e0e0")
    setc(QPalette.ColorRole.Base, "#1e1e1e")
    setc(QPalette.ColorRole.AlternateBase, "#1a1a1a")
    setc(QPalette.ColorRole.ToolTipBase, "#1e1e1e")
    setc(QPalette.ColorRole.ToolTipText, "#e0e0e0")
    setc(QPalette.ColorRole.Text, "#e0e0e0")
    setc(QPalette.ColorRole.Button, "#2d2d2d")
    setc(QPalette.ColorRole.ButtonText, "#e0e0e0")
    setc(QPalette.ColorRole.BrightText, "#f85149")
    setc(QPalette.ColorRole.Link, "#22d3ee")
    setc(QPalette.ColorRole.LinkVisited, "#a371f7")
    setc(QPalette.ColorRole.Highlight, "#0969da")
    setc(QPalette.ColorRole.HighlightedText, "#ffffff")
    setc(QPalette.ColorRole.PlaceholderText, "#7a7a7a")
    setc(QPalette.ColorRole.Light, "#3c3c3c")
    setc(QPalette.ColorRole.Midlight, "#333333")
    setc(QPalette.ColorRole.Mid, "#2a2a2a")
    setc(QPalette.ColorRole.Dark, "#252525")
    setc(QPalette.ColorRole.Shadow, "#000000")
    disabled = QPalette.ColorGroup.Disabled
    pal.setColor(disabled, QPalette.ColorRole.WindowText, "#6d6d6d")
    pal.setColor(disabled, QPalette.ColorRole.Text, "#6d6d6d")
    pal.setColor(disabled, QPalette.ColorRole.ButtonText, "#6d6d6d")
    pal.setColor(disabled, QPalette.ColorRole.Highlight, "#333333")
    pal.setColor(disabled, QPalette.ColorRole.HighlightedText, "#8a8a8a")
    return pal


# ---------------------------------------------------------------------------
# Threat Detection Engine
# ---------------------------------------------------------------------------

THREAT_PATTERNS: list[tuple[str, str, str]] = [
    ("AppData Execution", r"AppData\\", "high"),
    ("Temp Directory", r"\\Temp\\", "medium"),
    ("Public Folder", r"Users\\Public", "high"),
    ("PowerShell Script", r"\.ps1\b", "high"),
    ("Batch Script", r"\.bat\b", "medium"),
    ("VBScript", r"\.vbs\b", "high"),
    ("HTA Application", r"\.hta\b", "high"),
    ("JScript", r"\.js\b", "medium"),
    ("WSF Script", r"\.wsf\b", "high"),
    ("PowerShell Binary", r"powershell(?:\.exe)?", "high"),
    ("Cmd Binary", r"cmd(?:\.exe)?", "medium"),
    ("Rundll32", r"rundll32(?:\.exe)?", "high"),
    ("Regsvr32", r"regsvr32(?:\.exe)?", "high"),
    ("Mshta", r"mshta(?:\.exe)?", "high"),
    ("Certutil", r"certutil(?:\.exe)?", "high"),
    ("Bitsadmin", r"bitsadmin(?:\.exe)?", "high"),
    ("WMI Execution", r"wmic(?:\.exe)?", "high"),
    ("MSBuild", r"msbuild(?:\.exe)?", "high"),
    ("Installutil", r"installutil(?:\.exe)?", "high"),
    ("Encoded Command", r"-enc(?:odedcommand)?\s+", "high"),
    ("Suspicious Extension", r"\.(?:scr|pif|com|jar|msi)\b", "high"),
    ("Startup Folder", r"\\Startup\\", "high"),
    ("Run Key", r"\\Run\\", "medium"),
    ("Scheduled Task", r"schtasks(?:\.exe)?", "high"),
]


@dataclass
class ThreatMatch:
    rule_name: str
    severity: str
    matched_text: str


class ThreatEngine:
    def __init__(self):
        self._patterns: list[tuple[str, re.Pattern, str]] = []
        for name, pattern, severity in THREAT_PATTERNS:
            try:
                self._patterns.append((name, re.compile(pattern, re.IGNORECASE), severity))
            except re.error:
                continue

    def analyze(self, record: TimelineRecord) -> list[ThreatMatch]:
        matches: list[ThreatMatch] = []
        text = f"{record.target_path} {record.artifact_name} {record.event_type}"
        for name, pattern, severity in self._patterns:
            m = pattern.search(text)
            if m:
                matches.append(ThreatMatch(name, severity, m.group(0)))
        return matches

    def max_severity(self, matches: list[ThreatMatch]) -> Optional[str]:
        if not matches:
            return None
        severities = {m.severity for m in matches}
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        return "low"


# Shared instance: compiling the rule set once. Per-row ThreatEngine()
# constructions (132k+ regex compiles per filter on big timelines) froze
# the UI, so populate() paths must use this instead.
SHARED_THREAT_ENGINE = ThreatEngine()


# ---------------------------------------------------------------------------
# Artifact ingestion — routed exclusively through tier1_artifacts.py
# ---------------------------------------------------------------------------
# All parsing goes through the tested Tier 1 engine (AcquisitionEngine)
# and the direct robust parsers it reuses (lnk_forensics, prefetch_parser,
# jumplists_parser). The legacy parsers/ wrapper package was removed; there
# is intentionally no other ingestion path in this file. Run Analysis
# (ControlPanel.analysisRequested -> MainWindow._run_acquisition) is the
# single entry point from the GUI into acquisition.


def _record_sort_key(record: TimelineRecord):
    if record.dt is not None:
        return (0, record.dt)
    return (1, record.timestamp or "")


# ---------------------------------------------------------------------------
# AI Module
# ---------------------------------------------------------------------------

class AIAnalysisWorker(QThread):
    analysisComplete = Signal(str)
    analysisError = Signal(str)

    def __init__(self, api_key: str, endpoint: str, model: str,
                 prompt: str, parent=None):
        super().__init__(parent)
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._model = model
        self._prompt = prompt

    def run(self) -> None:
        try:
            payload = json.dumps({
                "model": self._model,
                "messages": [
                    {"role": "system", "content": "You are a senior DFIR analyst. Provide concise, professional forensic analysis."},
                    {"role": "user", "content": self._prompt},
                ],
                "max_tokens": 2048,
                "temperature": 0.3,
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{self._endpoint}/chat/completions",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self._api_key}",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                content = data["choices"][0]["message"]["content"]
                self.analysisComplete.emit(content)

        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            self.analysisError.emit(f"HTTP {exc.code}: {body}")
        except urllib.error.URLError as exc:
            self.analysisError.emit(f"Connection failed: {exc.reason}")
        except Exception as exc:
            self.analysisError.emit(f"Error: {exc}")


class AISettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI Analysis Settings")
        self.setMinimumWidth(480)

        settings = QSettings("DFIR", "TimelineAnalyzer")
        layout = QFormLayout(self)

        self.endpoint_input = QLineEdit()
        self.endpoint_input.setText(settings.value("ai_endpoint", "https://api.openai.com/v1"))
        layout.addRow("API Endpoint:", self.endpoint_input)

        self.api_key_input = QLineEdit()
        self.api_key_input.setText(settings.value("ai_api_key", ""))
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("API Key:", self.api_key_input)

        self.model_input = QLineEdit()
        self.model_input.setText(settings.value("ai_model", "gpt-4o-mini"))
        layout.addRow("Model:", self.model_input)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _save(self) -> None:
        settings = QSettings("DFIR", "TimelineAnalyzer")
        settings.setValue("ai_endpoint", self.endpoint_input.text().strip())
        settings.setValue("ai_api_key", self.api_key_input.text().strip())
        settings.setValue("ai_model", self.model_input.text().strip())
        self.accept()

    @staticmethod
    def get_settings() -> dict[str, str]:
        settings = QSettings("DFIR", "TimelineAnalyzer")
        return {
            "endpoint": settings.value("ai_endpoint", "https://api.openai.com/v1"),
            "api_key": settings.value("ai_api_key", ""),
            "model": settings.value("ai_model", "gpt-4o-mini"),
        }


class AIAnalysisDialog(QDialog):
    def __init__(self, analysis_text: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI Forensic Analysis")
        self.setMinimumSize(640, 480)

        layout = QVBoxLayout(self)

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setPlainText(analysis_text)
        layout.addWidget(self.text_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class TimelineRecord:
    timestamp: str
    dt: Optional[datetime]
    artifact_source: str
    event_type: str
    target_path: str
    machine_id: str
    artifact_name: str
    raw: dict = field(repr=False)
    search_blob: str = field(default="", repr=False)
    bookmarked: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        self.search_blob = " ".join(
            (self.timestamp, self.artifact_source, self.event_type,
             self.target_path, self.machine_id, self.artifact_name)
        ).lower()

    @property
    def chain(self) -> tuple[str, str, str]:
        return (self.machine_id, self.artifact_name, self.target_path)


def _first(obj: dict, *keys: str, default: str = "") -> str:
    for key in keys:
        value = obj.get(key)
        if value is None or value == "":
            continue
        return str(value)
    return default


def _parse_timestamp(value: Any) -> tuple[str, Optional[datetime]]:
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


def _detect_source(raw: dict) -> str:
    explicit = _first(raw, "artifact_source")
    if explicit:
        return explicit
    blob = f"{_first(raw, 'source')} {_first(raw, 'artifact_type')}".lower()
    if "prefetch" in blob:
        return "Prefetch"
    if "jumplist" in blob:
        return "JumpLists"
    if "shellbag" in blob:
        return "Shellbag"
    if "amcache" in blob:
        return "Amcache"
    if "srum" in blob:
        return "SRUM"
    if "userassist" in blob or "user_assist" in blob:
        return "UserAssist"
    if "bam" in blob:
        return "BAM"
    if "recentdoc" in blob:
        return "RecentDocs"
    if "recycle" in blob:
        return "RecycleBin"
    if "lnk" in blob or "shortcut" in blob:
        return "LNK"
    details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
    if _first(raw, "lnk_path", "lnk_file") or _first(details, "lnk_path", "lnk_file"):
        return "LNK"
    return _first(raw, "source", "artifact_type", default="Unknown")


def normalize_event(raw: dict) -> TimelineRecord:
    details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
    timestamp, moment = _parse_timestamp(
        _first(raw, "timestamp", "time", "datetime"))
    native_type = _first(raw, "event", "timestamp_type", "event_type", "activity")
    source = _detect_source(raw)
    machine = _first(details, "machine_id") or _first(
        raw, "machine_id", "computer_name", default="N/A")
    name = _first(raw, "lnk_file", "artifact_name", "prefetch_name",
                  "jumplists_name", "name") or \
        _first(details, "lnk_file", "lnk_path", default="N/A")
    target = _first(raw, "target_path", "path", "target", "shell_item_path") or \
        _first(details, "target_path", default="N/A")
    return TimelineRecord(
        timestamp=timestamp,
        dt=moment,
        artifact_source=source,
        event_type=EVENT_ALIASES.get(native_type, native_type or "Event"),
        target_path=target,
        machine_id=machine,
        artifact_name=name,
        raw=raw,
    )


def load_timeline(path: str | Path) -> tuple[list[TimelineRecord], dict[str, Any]]:
    path = Path(path)
    with open(path, "r", encoding="utf-8-sig") as handle:
        document = json.load(handle)

    meta: dict[str, Any] = {"path": str(path), "skipped": 0, "dropped": 0}
    if isinstance(document, list):
        events = document
    elif isinstance(document, dict):
        events = document.get("events", document.get("timeline"))
        if not isinstance(events, list):
            raise ValueError('The JSON object has no "events" list.')
        skipped = document.get("skipped") or []
        if isinstance(skipped, list):
            meta["skipped"] = len(skipped)
        elif skipped:
            try:
                meta["skipped"] = int(skipped)
            except (TypeError, ValueError):
                meta["skipped"] = 0
        metadata = document.get("metadata")
        if isinstance(metadata, dict):
            meta["metadata"] = metadata
    else:
        raise ValueError(
            "JSON root must be a list of events or an object with an events list.")

    records: list[TimelineRecord] = []
    dropped = 0
    for raw in events:
        if isinstance(raw, dict):
            try:
                records.append(normalize_event(raw))
            except Exception:
                dropped += 1
        else:
            dropped += 1
    meta["dropped"] = dropped

    records.sort(key=_record_sort_key)
    return records, meta


def load_timelines(paths: list[str | Path]) -> tuple[list[TimelineRecord], dict[str, Any]]:
    merged: list[TimelineRecord] = []
    loaded: list[str] = []
    skipped = 0
    dropped = 0
    failed: list[dict[str, str]] = []
    metadatas: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_path in paths:
        text = str(raw_path)
        if not text or text in seen:
            continue
        seen.add(text)
        try:
            records, meta = load_timeline(text)
        except FileNotFoundError as exc:
            failed.append({"file": text, "error": f"file not found ({exc})"})
            continue
        except json.JSONDecodeError as exc:
            failed.append({"file": text, "error": f"not valid JSON ({exc})"})
            continue
        except (OSError, ValueError) as exc:
            failed.append({"file": text, "error": str(exc)})
            continue
        loaded.append(meta.get("path", text))
        skipped += meta.get("skipped", 0) or 0
        dropped += meta.get("dropped", 0) or 0
        if isinstance(meta.get("metadata"), dict):
            metadatas.append(meta["metadata"])
        merged.extend(records)

    merged.sort(key=_record_sort_key)
    by_source: dict[str, int] = {}
    for record in merged:
        by_source[record.artifact_source] = by_source.get(record.artifact_source, 0) + 1
    return merged, {
        "paths": loaded,
        "skipped": skipped,
        "dropped": dropped,
        "failed": failed,
        "by_source": by_source,
        "metadatas": metadatas,
    }


# ---------------------------------------------------------------------------
# Export with SHA-256 Integrity
# ---------------------------------------------------------------------------

def _compute_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _export_csv(records: list[TimelineRecord], path: str) -> None:
    lines: list[str] = []
    header = ("Timestamp (UTC)", "Artifact Source", "Event Type",
              "Artifact Name", "Target Path", "Machine ID", "Bookmarked")
    lines.append(",".join(f'"{h}"' for h in header))
    for rec in records:
        row = (rec.timestamp, rec.artifact_source, rec.event_type,
               rec.artifact_name, rec.target_path, rec.machine_id,
               "Yes" if rec.bookmarked else "")
        lines.append(",".join(f'"{v.replace(chr(34), chr(34)+chr(34))}"' for v in row))

    data_text = "\n".join(lines)
    sha256 = _compute_sha256(data_text)

    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        fh.write(f"# SHA-256: {sha256}\n")
        fh.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        fh.write(f"# Events: {len(records)}\n")
        fh.write(data_text)


def _export_html(records: list[TimelineRecord], path: str, title: str,
                 subtitle: str = "") -> None:
    rows: list[str] = []
    for rec in records:
        color = ARTIFACT_COLORS.get(rec.artifact_source, "#8a8a8a")
        star = "\u2605" if rec.bookmarked else ""
        rows.append(f"""    <tr>
      <td>{html.escape(rec.timestamp)}</td>
      <td><span style="background:{color};color:#111;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:600">{html.escape(rec.artifact_source)}</span></td>
      <td>{html.escape(rec.event_type)}</td>
      <td>{html.escape(rec.artifact_name)}</td>
      <td>{html.escape(rec.target_path)}</td>
      <td>{html.escape(rec.machine_id)}</td>
      <td style="color:#f0883e;font-weight:700">{star}</td>
    </tr>""")

    table_rows = "\n".join(rows) if rows else \
        '    <tr><td colspan="7" style="text-align:center;color:#9a9a9a">No events to display</td></tr>'

    source_counts: dict[str, int] = {}
    n_bookmarked = 0
    for rec in records:
        source_counts[rec.artifact_source] = source_counts.get(rec.artifact_source, 0) + 1
        if rec.bookmarked:
            n_bookmarked += 1
    source_badges = " ".join(
        f'<span style="background:{ARTIFACT_COLORS.get(src, "#8a8a8a")};'
        f'color:#111;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:600'
        f';margin-right:6px">{html.escape(src)} ({cnt})</span>'
        for src, cnt in sorted(source_counts.items()))

    earliest = records[0].timestamp if records else "N/A"
    latest = records[-1].timestamp if records else "N/A"

    data_text = f"{earliest}{latest}{len(records)}"
    for rec in records:
        data_text += f"{rec.timestamp}{rec.artifact_source}{rec.target_path}"
    sha256 = _compute_sha256(data_text)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="sha256" content="{sha256}">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#121212; color:#e0e0e0; margin:40px; }}
    h1 {{ color:#fff; margin-bottom:4px; }}
    h2 {{ color:#9a9a9a; font-size:14px; font-weight:400; margin-top:0; }}
    .meta {{ color:#9a9a9a; font-size:12px; margin-bottom:8px; }}
    .filters {{ color:#22d3ee; font-size:12px; margin-bottom:20px; }}
    .hash {{ font-family: monospace; background:#1e1e1e; padding:8px 12px; border-radius:4px; border:1px solid #3c3c3c; margin-bottom:20px; font-size:12px; }}
    .hash strong {{ color:#58a6ff; }}
    .badges {{ margin-bottom:20px; }}
    table {{ border-collapse:collapse; width:100%; font-size:13px; }}
    th {{ background:#1e1e1e; color:#e0e0e0; text-align:left; padding:8px 10px; border:1px solid #333333; }}
    td {{ padding:6px 10px; border:1px solid #333333; vertical-align:top; }}
    tr:nth-child(even) {{ background:#1a1a1a; }}
  </style>
</head>
<body>
  <h1>{html.escape(title)}</h1>
  <h2>DFIR Timeline Analyzer \u2014 forensic report</h2>
  <div class="meta">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} &middot;
    {len(records):,} events &middot; {n_bookmarked} bookmarked &middot; Time range: {html.escape(earliest)} &rarr; {html.escape(latest)}</div>
  <div class="filters">{html.escape(subtitle) if subtitle else "No filters (full dataset)"}</div>
  <div class="hash"><strong>SHA-256:</strong> {sha256}</div>
  <div class="badges">{source_badges}</div>
  <table>
    <thead>
      <tr><th>Timestamp (UTC)</th><th>Source</th><th>Event</th>
          <th>Artifact Name</th><th>Target Path</th><th>Machine ID</th><th>\u2605</th></tr>
    </thead>
    <tbody>
{table_rows}
    </tbody>
  </table>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)


# ---------------------------------------------------------------------------
# UI Components
# ---------------------------------------------------------------------------

class TimelineTable(QTableWidget):
    recordSelected = Signal(object)
    bookmarkToggled = Signal(object)

    COLUMNS = (
        "\u2605",
        "Timestamp (UTC)",
        "Artifact Source",
        "Target Path",
        "Machine ID",
        "Event Type",
        "Artifact Name",
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self.records: list[TimelineRecord] = []
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)
        vertical = self.verticalHeader()
        vertical.setVisible(False)
        vertical.setDefaultSectionSize(26)
        header = self.horizontalHeader()
        header.setHighlightSections(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.setColumnWidth(0, 36)
        self.setColumnWidth(1, 238)
        self.setColumnWidth(4, 140)
        self.setColumnWidth(6, 230)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSortingEnabled(False)
        self.setWordWrap(False)
        self.setShowGrid(True)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_context_menu)
        self.itemSelectionChanged.connect(self._on_selection)

    def populate(self, records: list[TimelineRecord],
                 threat_map: Optional[dict[int, list[ThreatMatch]]] = None) -> None:
        self.setSortingEnabled(False)
        self.blockSignals(True)
        try:
            self.setRowCount(0)
            self.setRowCount(len(records))
            for row, record in enumerate(records):
                values = (
                    "\u2605" if record.bookmarked else "",
                    record.timestamp,
                    record.artifact_source,
                    record.target_path,
                    record.machine_id,
                    record.event_type,
                    record.artifact_name,
                )
                for column, text in enumerate(values):
                    item = QTableWidgetItem(text)
                    item.setToolTip(text)
                    if column == 0:
                        item.setData(Qt.ItemDataRole.UserRole, record)
                        if record.bookmarked:
                            item.setForeground(QColor("#f0883e"))
                            font = item.font()
                            font.setBold(True)
                            item.setFont(font)
                    self.setItem(row, column, item)
                if threat_map:
                    threats = threat_map.get(id(record), [])
                    severity = SHARED_THREAT_ENGINE.max_severity(threats)
                    if severity == "high":
                        for column in range(len(values)):
                            self.item(row, column).setBackground(QColor("#5c1a1a"))
                    elif severity == "medium":
                        for column in range(len(values)):
                            self.item(row, column).setBackground(QColor("#3d2e0a"))
        finally:
            self.blockSignals(False)
            self.setSortingEnabled(True)
        self.records = records

    def find_row(self, record: TimelineRecord) -> int:
        for row, candidate in enumerate(self.records):
            if candidate is record:
                return row
        return -1

    def _on_selection(self) -> None:
        items = self.selectedItems()
        if not items:
            self.recordSelected.emit(None)
            return
        row = items[0].row()
        holder = self.item(row, 0)
        record = holder.data(Qt.ItemDataRole.UserRole) if holder else None
        self.recordSelected.emit(record)

    def _record_at(self, pos) -> Optional[TimelineRecord]:
        item = self.itemAt(pos)
        if item is None:
            return None
        holder = self.item(item.row(), 0)
        record = holder.data(Qt.ItemDataRole.UserRole) if holder else None
        return record if isinstance(record, TimelineRecord) else None

    def _on_context_menu(self, pos) -> None:
        record = self._record_at(pos)
        if record is None:
            return
        menu = QMenu(self)
        action = menu.addAction(
            "\u2605 Remove bookmark" if record.bookmarked else "\u2606 Bookmark event")
        if menu.exec(self.viewport().mapToGlobal(pos)) == action:
            self.bookmarkToggled.emit(record)


class MasterTimelinePanel(QWidget):
    recordSelected = Signal(object)
    traceOriginRequested = Signal(object)
    bookmarkToggled = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records: list[TimelineRecord] = []
        self._threat_map: dict[int, list[ThreatMatch]] = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(4)
        self._tree.setHeaderLabels(["", "Timestamp", "Source", "Event / Target"])
        self._tree.setAlternatingRowColors(True)
        self._tree.setRootIsDecorated(False)
        self._tree.setUniformRowHeights(True)
        self._tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tree.setWordWrap(False)
        self._tree.setColumnWidth(0, 10)
        self._tree.setColumnWidth(1, 200)
        self._tree.setColumnWidth(2, 90)
        header = self._tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._tree.itemSelectionChanged.connect(self._on_selection)
        self._tree.itemDoubleClicked.connect(self._on_double_click)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._show_context_menu)
        root.addWidget(self._tree)

    def populate(self, records: list[TimelineRecord],
                 threat_map: Optional[dict[int, list[ThreatMatch]]] = None) -> None:
        self._records = list(records)
        self._threat_map = threat_map or {}
        self._tree.setUpdatesEnabled(False)
        try:
            self._tree.clear()
            items = []
            for rec in self._records:
                color = ARTIFACT_COLORS.get(rec.artifact_source, "#8a8a8a")
                display_target = rec.target_path if rec.target_path != "N/A" else rec.artifact_name
                star = "\u2605 " if rec.bookmarked else ""
                detail = f"{star}{rec.event_type} \u2014 {display_target}"
                item = QTreeWidgetItem([
                    "",
                    rec.timestamp,
                    rec.artifact_source,
                    detail,
                ])
                item.setData(0, Qt.ItemDataRole.UserRole, rec)
                # Flat color swatch: no per-row widgets, so thousands of
                # rows stay cheap (QLabel-per-row hung the UI on big loads).
                item.setBackground(0, QBrush(QColor(color)))
                item.setToolTip(0, rec.artifact_source)
                item.setToolTip(1, rec.timestamp)
                item.setToolTip(2, rec.artifact_source)
                item.setToolTip(3, detail)
                if rec.artifact_source in ARTIFACT_COLORS:
                    item.setForeground(2, QColor(color))
                if rec.bookmarked:
                    item.setForeground(3, QColor("#f0883e"))
                threats = self._threat_map.get(id(rec), [])
                severity = ThreatEngine().max_severity(threats)
                if severity == "high":
                    for col in range(4):
                        item.setBackground(col, QColor("#5c1a1a"))
                elif severity == "medium":
                    for col in range(4):
                        item.setBackground(col, QColor("#3d2e0a"))
                items.append(item)
            self._tree.addTopLevelItems(items)
        finally:
            self._tree.setUpdatesEnabled(True)

    def _on_selection(self) -> None:
        items = self._tree.selectedItems()
        if not items:
            self.recordSelected.emit(None)
            return
        rec = items[0].data(0, Qt.ItemDataRole.UserRole)
        self.recordSelected.emit(rec if isinstance(rec, TimelineRecord) else None)

    def _on_double_click(self, item: QTreeWidgetItem, _col: int) -> None:
        rec = item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(rec, TimelineRecord):
            self.recordSelected.emit(rec)

    def _show_context_menu(self, pos) -> None:
        item = self._tree.itemAt(pos)
        if not item:
            return
        rec = item.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(rec, TimelineRecord):
            return
        menu = QMenu(self)
        bookmark_action = menu.addAction(
            "\u2605 Remove bookmark" if rec.bookmarked else "\u2606 Bookmark event")
        trace_action = menu.addAction("Trace Origin")
        chosen = menu.exec(self._tree.viewport().mapToGlobal(pos))
        if chosen == bookmark_action:
            self.bookmarkToggled.emit(rec)
        elif chosen == trace_action:
            self.traceOriginRequested.emit(rec)


class ShellbagsExplorer(QWidget):
    """Folder hierarchy tree (left) + nested item inspection table (right).

    Parses Shellbag / RecycleBin / RecentDocs records into a directory tree.
    Clicking a folder populates the adjacent table with its contents and
    flags each item as Active / Deleted / Moved / Renamed.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records: list[TimelineRecord] = []
        self._tree_index: dict[QTreeWidgetItem, list[TimelineRecord]] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ---- left: folder hierarchy tree ----
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(4, 4, 4, 4)
        left_layout.setSpacing(4)

        left_header = QLabel("Folder Hierarchy")
        left_header.setObjectName("panelTitle")
        left_layout.addWidget(left_header)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(2)
        self._tree.setHeaderLabels(["Folder", "Items"])
        self._tree.setAlternatingRowColors(True)
        self._tree.setRootIsDecorated(True)
        self._tree.setUniformRowHeights(True)
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tree.setColumnWidth(0, 280)
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._tree.setColumnWidth(1, 60)
        self._tree.itemSelectionChanged.connect(self._on_tree_selection)
        left_layout.addWidget(self._tree, 1)
        splitter.addWidget(left)

        # ---- right: nested item detail table ----
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(4, 4, 4, 4)
        right_layout.setSpacing(4)

        right_header = QLabel("Folder Contents")
        right_header.setObjectName("panelTitle")
        right_layout.addWidget(right_header)

        self._detail = QTableWidget()
        self._detail.setColumnCount(5)
        self._detail.setHorizontalHeaderLabels(
            ["Status", "Item Name", "Last Modified", "Source", "Size / Notes"])
        self._detail.setAlternatingRowColors(True)
        self._detail.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self._detail.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self._detail.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self._detail.verticalHeader().setVisible(False)
        self._detail.verticalHeader().setDefaultSectionSize(24)
        dh = self._detail.horizontalHeader()
        dh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        dh.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        dh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        dh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        dh.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self._detail.setColumnWidth(0, 90)
        self._detail.setColumnWidth(2, 180)
        self._detail.setColumnWidth(3, 90)
        right_layout.addWidget(self._detail, 1)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([420, 860])
        root.addWidget(splitter, 1)

        # ---- bottom summary bar ----
        self._summary = QLabel("")
        self._summary.setWordWrap(True)
        root.addWidget(self._summary)

    # ------------------------------------------------------------------
    # population
    # ------------------------------------------------------------------

    def populate(self, records: list[TimelineRecord]) -> None:
        self._records = list(records)
        self._tree.setUpdatesEnabled(False)
        self._detail.setUpdatesEnabled(False)
        try:
            self._tree.clear()
            self._detail.setRowCount(0)
            self._tree_index.clear()

            deleted_count = 0
            moved_count = 0
            renamed_count = 0
            active_count = 0

            shell_records = [
                r for r in self._records
                if r.artifact_source in ("Shellbag", "RecycleBin", "RecentDocs")
            ]

            for rec in shell_records:
                status, color, _ = self._classify(rec)
                if status == "DELETED":
                    deleted_count += 1
                elif status == "MOVED":
                    moved_count += 1
                elif status == "RENAMED":
                    renamed_count += 1
                else:
                    active_count += 1

                self._insert_into_tree(rec)

            self._tree.expandToDepth(1)

            total_shell = len(shell_records)
            if total_shell == 0:
                self._summary.setText(
                    "No shell items loaded — run <b>Run Analysis</b> with the "
                    "'Shellbags' checkbox ticked (or load a timeline that "
                    "contains source <b>Shellbag</b>).")
            else:
                self._summary.setText(
                    f"Shell items: {total_shell} | "
                    f"<span style='color:#3fb950'>Active: {active_count}</span> | "
                    f"<span style='color:#f85149'>Deleted: {deleted_count}</span> | "
                    f"<span style='color:#d29922'>Moved: {moved_count}</span> | "
                    f"<span style='color:#a371f7'>Renamed: {renamed_count}</span>")
        finally:
            self._tree.setUpdatesEnabled(True)
            self._detail.setUpdatesEnabled(True)

    @staticmethod
    def _classify(rec: TimelineRecord) -> tuple[str, str, str]:
        """Return (status_text, color, details) for a shell record."""
        raw = rec.raw
        if rec.artifact_source == "RecycleBin":
            size = raw.get("orig_size", "")
            details = f"Size: {size}" if size else ""
            return "DELETED", "#f85149", details
        if rec.artifact_source == "Shellbag":
            if raw.get("deleted"):
                return "MOVED", "#d29922", ""
            if raw.get("renamed"):
                return "RENAMED", "#a371f7", ""
            return "ACTIVE", "#3fb950", ""
        return "ACTIVE", "#3fb950", ""

    def _insert_into_tree(self, rec: TimelineRecord) -> None:
        """Insert *rec* into the folder hierarchy, creating parents as needed."""
        path = rec.target_path
        if not path or path == "N/A":
            path = rec.artifact_name or "Unknown"

        parts = [p for p in path.replace("/", "\\").split("\\") if p]
        if not parts:
            parts = ["Unknown"]

        parent = self._tree.invisibleRootItem()
        current_path_parts: list[str] = []

        for part in parts:
            current_path_parts.append(part)
            full = "\\".join(current_path_parts)
            child = self._find_child(parent, part)
            if child is None:
                child = QTreeWidgetItem(parent, [part, "0"])
                child.setData(0, Qt.ItemDataRole.UserRole, full)
                child.setForeground(0, QColor("#d4d4d4"))
                child.setFont(0, QFont("Segoe UI", 9))
            parent = child

            # attach the record to every ancestor so that selecting any
            # folder node lists all items nested beneath it.
            bucket = self._tree_index.get(child, [])
            bucket.append(rec)
            self._tree_index[child] = bucket
            child.setText(1, str(len(bucket)))

    @staticmethod
    def _find_child(parent: QTreeWidgetItem, name: str) -> Optional[QTreeWidgetItem]:
        for i in range(parent.childCount()):
            child = parent.child(i)
            if child and child.text(0) == name:
                return child
        return None

    # ------------------------------------------------------------------
    # detail table
    # ------------------------------------------------------------------

    def _on_tree_selection(self) -> None:
        items = self._tree.selectedItems()
        if not items:
            self._detail.setRowCount(0)
            return
        # union records across every selected node (deduplicated), so the
        # detail table is correct even if more than one node is selected.
        seen: dict[int, TimelineRecord] = {}
        ordered: list[TimelineRecord] = []
        for item in items:
            for rec in self._tree_index.get(item, []):
                key = id(rec)
                if key not in seen:
                    seen[key] = rec
                    ordered.append(rec)
        ordered.sort(key=lambda r: r.timestamp)
        self._populate_detail(ordered)

    def _populate_detail(self, records: list[TimelineRecord]) -> None:
        self._detail.setRowCount(0)
        self._detail.setRowCount(len(records))
        for row, rec in enumerate(records):
            status, color, details = self._classify(rec)
            display_name = rec.artifact_name or Path(rec.target_path).name
            values = [status, display_name, rec.timestamp,
                      rec.artifact_source, details]
            for col, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                item.setToolTip(str(text))
                self._detail.setItem(row, col, item)
            # colour the status cell
            self._detail.item(row, 0).setForeground(QColor(color))
            # colour the source cell
            src_color = ARTIFACT_COLORS.get(rec.artifact_source, "#8a8a8a")
            self._detail.item(row, 3).setForeground(QColor(src_color))


class ArtifactSubView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._records: list[TimelineRecord] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(5)
        self._tree.setHeaderLabels(["Timestamp", "Source", "Event", "Artifact", "Details"])
        self._tree.setAlternatingRowColors(True)
        self._tree.setRootIsDecorated(False)
        self._tree.setUniformRowHeights(True)
        header = self._tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._tree.setColumnWidth(0, 200)
        self._tree.setColumnWidth(1, 90)
        self._tree.setColumnWidth(2, 120)
        root.addWidget(self._tree)

    def populate(self, records: list[TimelineRecord], sub_view_type: str) -> None:
        self._records = list(records)
        self._tree.setUpdatesEnabled(False)
        try:
            self._tree.clear()
            for rec in self._records:
                raw = rec.raw
                if sub_view_type == "Executions":
                    if rec.artifact_source not in ("Prefetch", "UserAssist", "BAM"):
                        continue
                elif sub_view_type == "Loaded Files":
                    if rec.artifact_source not in ("LNK", "JumpLists", "Amcache"):
                        continue
                elif sub_view_type == "Metadata":
                    if rec.artifact_source not in ("Shellbag", "RecentDocs",
                                                   "RegistryMRU"):
                        continue
                elif sub_view_type == "Bin Items":
                    if rec.artifact_source != "RecycleBin":
                        continue

                details = ""
                if "run_count" in raw:
                    details = f"Runs: {raw['run_count']}"
                elif "sha1" in raw:
                    details = f"SHA1: {raw['sha1']}"
                elif "orig_size" in raw:
                    details = f"Size: {raw['orig_size']}"
                elif "user_sid" in raw:
                    details = f"SID: {raw['user_sid']}"
                else:
                    details = str(raw)[:80]

                item = QTreeWidgetItem(self._tree, [
                    rec.timestamp,
                    rec.artifact_source,
                    rec.event_type,
                    rec.artifact_name,
                    details,
                ])
                color = ARTIFACT_COLORS.get(rec.artifact_source, "#8a8a8a")
                item.setForeground(1, QColor(color))
        finally:
            self._tree.setUpdatesEnabled(True)


def _scalar_text(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


class InspectorPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        self.header = QLabel(
            "Select a row in the Timeline Table to inspect its raw properties.")
        self.header.setObjectName("mutedLabel")
        self.header.setWordWrap(True)
        root.addWidget(self.header)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(2)
        self.tree.setHeaderLabels(["Property", "Value"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setRootIsDecorated(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        header = self.tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.tree, 1)

    def clear(self) -> None:
        self.tree.clear()
        self.header.setText(
            "Select a row in the Timeline Table to inspect its raw properties.")

    def show_record(self, record: TimelineRecord) -> None:
        self.tree.setUpdatesEnabled(False)
        try:
            self.tree.clear()
            self.header.setText(
                f"{record.artifact_source}  \u00b7  {record.timestamp}  \u00b7  {record.artifact_name}")
            raw = record.raw
            if isinstance(raw, dict):
                for key, value in raw.items():
                    self._add_node(None, str(key), value)
            elif isinstance(raw, list):
                for index, value in enumerate(raw):
                    self._add_node(None, str(index), value)
            else:
                self._add_node(None, "payload", raw)
            for index in range(self.tree.topLevelItemCount()):
                node = self.tree.topLevelItem(index)
                # Auto-expand small nodes only: expanding a huge list (e.g.
                # Prefetch referenced_files) froze the UI on selection.
                if 0 < node.childCount() <= 100:
                    node.setExpanded(True)
            if self.tree.topLevelItemCount():
                self.tree.setCurrentItem(self.tree.topLevelItem(0))
        finally:
            self.tree.setUpdatesEnabled(True)

    def _add_node(self, parent: Optional[QTreeWidgetItem], key: str, value: Any) -> None:
        if isinstance(value, dict):
            node = QTreeWidgetItem(
                self.tree if parent is None else parent, [key, ""])
            for child_key, child_value in value.items():
                self._add_node(node, str(child_key), child_value)
        elif isinstance(value, list):
            node = QTreeWidgetItem(
                self.tree if parent is None else parent,
                [key, f"list \u00b7 {len(value)} items"])
            for index, child_value in enumerate(value):
                self._add_node(node, f"[{index}]", child_value)
        else:
            text = _scalar_text(value)
            node = QTreeWidgetItem(
                self.tree if parent is None else parent, [key, text])
            if len(text) > 60:
                node.setToolTip(1, text)


class NodeItem(QGraphicsRectItem):
    def __init__(self, stage: str, title: str, value: str, x: float, y: float,
                 accent_color: Optional[str] = None):
        super().__init__(x, y, NODE_W, NODE_H)
        self.stage = stage
        self.title = title
        self.value = value
        self._accent = QColor(accent_color or STAGE_COLORS.get(stage, "#58a6ff"))
        self._active = False
        self.setAcceptHoverEvents(True)
        self.setZValue(2)
        self.setToolTip(f"{title}\n{value}")

    def boundingRect(self) -> QRectF:
        return super().boundingRect().adjusted(-3, -3, 3, 3)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        rect = self.rect()
        path = QPainterPath()
        path.addRoundedRect(rect, 8, 8)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#1e1e1e"))
        painter.drawPath(path)
        painter.save()
        painter.setClipPath(path)
        painter.setBrush(self._accent)
        painter.drawRect(QRectF(rect.left(), rect.top(), 5, rect.height()))
        painter.restore()
        pen = QPen(self._accent if self._active
                   else QColor("#333333"))
        pen.setWidthF(2.0 if self._active else 1.0)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)
        inner = rect.adjusted(16, 0, -12, 0)
        painter.setPen(QColor("#f5f5f5"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.DemiBold))
        painter.drawText(
            QRectF(inner.left(), inner.top() + 10, inner.width(), 22),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            self.title)
        painter.setPen(QColor("#bdbdbd"))
        painter.setFont(QFont("Segoe UI", 8))
        elided = QFontMetrics(painter.font()).elidedText(
            self.value, Qt.TextElideMode.ElideMiddle, int(inner.width()))
        painter.drawText(
            QRectF(inner.left(), inner.top() + 40, inner.width(), 26),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            elided)

    def set_active(self, active: bool) -> None:
        if self._active != active:
            self._active = active
            self.update()


class EdgeItem(QGraphicsPathItem):
    def __init__(self, source: NodeItem, target: NodeItem, color: str = "#4f4f4f"):
        start = source.mapToScene(
            QPointF(source.rect().right(), source.rect().center().y()))
        end = target.mapToScene(
            QPointF(target.rect().left(), target.rect().center().y()))
        dx = end.x() - start.x()
        ctrl_offset = max(40.0, dx * 0.4)
        path = QPainterPath(start)
        path.cubicTo(
            QPointF(start.x() + ctrl_offset, start.y()),
            QPointF(end.x() - ctrl_offset, end.y()),
            end)
        super().__init__(path)
        self._color = QColor(color)
        pen = QPen(self._color, 1.5)
        pen.setCosmetic(True)
        self.setPen(pen)
        self.setZValue(1)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        super().paint(painter, option, widget)
        path = self.path()
        tip = path.pointAtPercent(1.0)
        previous = path.pointAtPercent(0.94)
        dx = tip.x() - previous.x()
        dy = tip.y() - previous.y()
        length = math.hypot(dx, dy)
        if length < 1e-6:
            return
        ux, uy = dx / length, dy / length
        nx, ny = -uy, ux
        base = QPointF(tip.x() - ux * 9, tip.y() - uy * 9)
        wing_a = QPointF(base.x() + nx * 4, base.y() + ny * 4)
        wing_b = QPointF(base.x() - nx * 4, base.y() - ny * 4)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self._color)
        painter.drawPolygon(QPolygonF([tip, wing_a, wing_b]))


class CardItem(QGraphicsRectItem):
    """One cluster card for the overview grid.

    Summarizes a (machine, artifact) cluster: artifact name, host, target /
    event counts, most-recent target and timestamp. Clicking a card drills
    into the cluster's full chain view (handled by RelationshipGraphView).
    """

    def __init__(self, key: tuple[str, str], facts: dict, x: float, y: float):
        super().__init__(x, y, CARD_W, CARD_H)
        self.key = key
        self.facts = facts
        self._hover = False
        self._accent = QColor(ARTIFACT_COLORS.get(facts.get("source", ""), "#8a8a8a"))
        self.setAcceptHoverEvents(True)
        self.setZValue(2)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(
            f"{facts.get('source', 'Unknown')} \u00b7 {facts.get('artifact', '')}\n"
            f"Machine: {facts.get('machine', '')}\n"
            f"{facts.get('count', 0)} targets \u00b7 {facts.get('events', 0)} events\n"
            f"Latest: {facts.get('target', '')}\n"
            f"{facts.get('latest_str', '')}\nClick to drill into this cluster")

    def boundingRect(self) -> QRectF:
        return super().boundingRect().adjusted(-3, -3, 3, 3)

    def _line(self, painter: QPainter, text: str, y: float, height: float,
              color: QColor, bold: bool = False, size: int = 8) -> None:
        inner = self.rect().adjusted(16, 0, -12, 0)
        font = QFont("Segoe UI", size, QFont.Weight.DemiBold if bold else QFont.Weight.Normal)
        painter.setFont(font)
        painter.setPen(color)
        elided = QFontMetrics(font).elidedText(text, Qt.TextElideMode.ElideRight,
                                               int(inner.width()))
        painter.drawText(QRectF(inner.left(), y, inner.width(), height),
                         Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                         elided)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        rect = self.rect()
        path = QPainterPath()
        path.addRoundedRect(rect, 8, 8)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#1e1e1e") if not self._hover else QColor("#232323"))
        painter.drawPath(path)
        painter.save()
        painter.setClipPath(path)
        painter.setBrush(self._accent)
        painter.drawRect(QRectF(rect.left(), rect.top(), 5, rect.height()))
        painter.restore()
        pen = QPen(self._accent if self._hover else QColor("#333333"))
        pen.setWidthF(2.0 if self._hover else 1.0)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)
        facts = self.facts
        self._line(painter, str(facts.get("artifact", "")), rect.top() + 6, 22,
                   QColor("#f5f5f5"), bold=True, size=9)
        self._line(painter, str(facts.get("machine", "")), rect.top() + 28, 18,
                   QColor("#bdbdbd"))
        self._line(painter,
                   f"{facts.get('count', 0)} targets \u00b7 {facts.get('events', 0)} events",
                   rect.top() + 46, 18, QColor("#e0e0e0"))
        self._line(painter, str(facts.get("target", "")), rect.top() + 64, 18,
                   QColor("#9a9a9a"))
        latest_str = facts.get("latest_str", "")
        if latest_str:
            self._line(painter, latest_str, rect.top() + 82, 18, QColor("#6d6d6d"))

    def hoverEnterEvent(self, event) -> None:
        self._hover = True
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event) -> None:
        self._hover = False
        self.update()
        super().hoverLeaveEvent(event)


class RelationshipGraphView(QGraphicsView):
    traceOriginRequested = Signal(object)
    clusterSelected = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHints(
            QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing)
        self.setBackgroundBrush(QColor("#121212"))
        self.setViewportUpdateMode(
            QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(
            QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._records: list[TimelineRecord] = []
        self._focus: Optional[TimelineRecord] = None
        self._focus_cluster: Optional[tuple[str, str]] = None
        self._nodes: dict[tuple[str, str], NodeItem] = {}
        self._cards: list[CardItem] = []
        self._page = 0
        self._cols = 3
        self._overview_counts = (0, 0, 0)
        self._press_item = None
        self._press_pos = None
        self._scale = 1.0
        self._pending_fit = False
        self._fitted_for: Optional[QSize] = None
        self._user_zoomed = False
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

    def set_data(self, records: list[TimelineRecord],
                 focus: Optional[TimelineRecord] = None,
                 refit: bool = True) -> None:
        self._records = list(records)
        self._focus = focus
        self._focus_cluster = None
        self._page = 0
        self._rebuild()
        if refit:
            self._user_zoomed = False
            self._pending_fit = True
            QTimer.singleShot(0, self._try_fit)
        elif focus is not None:
            self._ensure_focus_visible()

    def focus_cluster(self, key: tuple[str, str]) -> None:
        """Drill into one (machine, artifact) cluster's chain view."""
        self._focus = None
        self._focus_cluster = (str(key[0]), str(key[1]))
        self._page = 0
        self._rebuild()
        self._ensure_focus_visible()

    def show_overview(self) -> None:
        self._focus = None
        self._focus_cluster = None
        self._page = 0
        self._rebuild()

    def pager_visible(self) -> bool:
        return self._focus_cluster is not None and self.page_count() > 1

    def overview_active(self) -> bool:
        return self._focus is None and self._focus_cluster is None

    # -- pagination API (focus-cluster mode only; overview scrolls freely) --
    def _cluster_chain_count(self) -> int:
        if self._focus_cluster is None:
            return 0
        return len({r.chain for r in self._records
                    if (r.machine_id, r.artifact_name) == self._focus_cluster})

    def page_count(self) -> int:
        if self._focus_cluster is None or not self._records:
            return 1
        return max(1, -(-self._cluster_chain_count() // CHAINS_PER_PAGE))

    def page_info(self) -> str:
        if self._focus is not None:
            return "Focused chain"
        if self._focus_cluster is not None:
            machine, artifact = self._focus_cluster
            pages = self.page_count()
            total = self._cluster_chain_count()
            base = (f"Cluster \u2014 {artifact} on {machine} "
                    f"\u00b7 {total:,} chains")
            if pages > 1:
                base += f" \u00b7 page {self._page + 1}/{pages}"
            return base
        if not self._records:
            return "No data"
        nclusters, nchains, nevents = self._overview_counts
        return (f"Overview \u2014 {nclusters} clusters \u00b7 {nchains:,} chains "
                f"\u00b7 {nevents:,} events \u2014 click a card to drill in")

    def goto_page(self, page: int) -> bool:
        if self._focus_cluster is None:
            return False
        pages = self.page_count()
        clamped = max(0, min(page, pages - 1))
        if clamped == self._page:
            return False
        self._page = clamped
        self._rebuild()
        self._user_zoomed = False
        self._pending_fit = True
        QTimer.singleShot(0, self._try_fit)
        return True

    def next_page(self) -> bool:
        return self.goto_page(self._page + 1)

    def prev_page(self) -> bool:
        return self.goto_page(self._page - 1)

    def _all_chains(self) -> tuple[list[tuple[str, str, str]], dict]:
        """Every unique chain, most-recent-first (no truncation)."""
        dated = [record for record in self._records if record.dt is not None]
        undated = [record for record in self._records if record.dt is None]
        dated.sort(key=lambda record: record.dt, reverse=True)
        chains: list[tuple[str, str, str]] = []
        chain_sources: dict = {}
        seen: set[tuple[str, str, str]] = set()
        for record in dated + undated:
            chain = record.chain
            if chain in seen:
                continue
            seen.add(chain)
            chains.append(chain)
            chain_sources.setdefault(chain, record.artifact_source)
        return chains, chain_sources

    def _clusters(self, chains=None, chain_sources=None) -> list[dict]:
        """Group chains by (machine, artifact) with event counts and recency.

        Input order is recency order, so each group's first row carries its
        latest target. Every group also aggregates its event total and
        latest timestamp for card display.
        """
        if chains is None or chain_sources is None:
            chains, chain_sources = self._all_chains()
        event_counts: dict = {}
        latest: dict = {}
        for record in self._records:
            event_counts[record.chain] = event_counts.get(record.chain, 0) + 1
            if record.dt is not None:
                if record.chain not in latest or record.dt > latest[record.chain]:
                    latest[record.chain] = record.dt
        groups: dict[tuple[str, str], dict] = {}
        for chain in chains:
            machine, artifact, target = chain
            key = (machine, artifact)
            entry = groups.get(key)
            if entry is None:
                moment = latest.get(chain)
                groups[key] = {"machine": machine, "artifact": artifact,
                               "target": target,
                               "source": chain_sources.get(chain, "Unknown"),
                               "count": 1,
                               "events": event_counts.get(chain, 0),
                               "latest": moment,
                               "latest_str": (moment.isoformat(timespec="seconds")
                                              if moment else "")}
            else:
                entry["count"] += 1
                entry["events"] += event_counts.get(chain, 0)
        return list(groups.values())

    def _cluster_chain_rows(self, key: tuple[str, str]) -> list[tuple]:
        """Recency-ordered (machine, artifact, target, source) rows of a cluster."""
        chains, chain_sources = self._all_chains()
        return [(m, a, t, chain_sources.get((m, a, t), "Unknown"))
                for (m, a, t) in chains if (m, a) == (str(key[0]), str(key[1]))]

    def _rebuild(self) -> None:
        self._scene.clear()
        self._nodes.clear()
        self._cards = []
        focus = self._focus
        if not self._records:
            self._add_caption("No timeline loaded \u2014 open a JSON timeline "
                              "to view artifact relationships.")
            self._scene.setSceneRect(QRectF(0, 0, 920, 140))
            return

        if focus is not None:
            self._rebuild_chain_rows(
                [(focus.chain[0], focus.chain[1], focus.chain[2],
                  focus.artifact_source)],
                caption=(f"Focused chain \u2014 {focus.artifact_source} \u00b7 "
                         f"{focus.artifact_name} \u2192 {focus.target_path}"),
                activate=True)
        elif self._focus_cluster is not None:
            rows = self._cluster_chain_rows(self._focus_cluster)
            total = len(rows)
            pages = max(1, -(-total // CHAINS_PER_PAGE))
            self._page = max(0, min(self._page, pages - 1))
            window = rows[self._page * CHAINS_PER_PAGE:
                          self._page * CHAINS_PER_PAGE + CHAINS_PER_PAGE]
            machine, artifact = self._focus_cluster
            source = window[0][3] if window else "Unknown"
            caption = (f"Cluster \u2014 {source} \u00b7 {artifact} on {machine} "
                       f"\u00b7 {total:,} chains")
            if pages > 1:
                caption += f" \u00b7 page {self._page + 1}/{pages}"
            self._rebuild_chain_rows(window, caption=caption, activate=False)
        else:
            self._rebuild_overview_cards()

    def _rebuild_chain_rows(self, rows, caption: str, activate: bool) -> None:
        """Classic 3-stage hierarchical layout for a bounded row window."""
        self._add_caption(caption)
        columns = {
            "machine": 0.0,
            "artifact": NODE_W + COL_GAP,
            "target": 2 * (NODE_W + COL_GAP),
        }
        placed: dict[tuple[str, str], NodeItem] = {}
        for row, (machine, artifact, target, source, *_rest) in enumerate(rows):
            y = MARGIN + row * (NODE_H + ROW_GAP)
            for stage, value, title, accent in (
                ("machine", machine, STAGE_TITLES["machine"],
                 STAGE_COLORS["machine"]),
                ("artifact", artifact, source,
                 ARTIFACT_COLORS.get(source, "#8a8a8a")),
                ("target", target, STAGE_TITLES["target"],
                 STAGE_COLORS["target"]),
            ):
                key = (stage, value)
                if key in placed:
                    continue
                placed[key] = NodeItem(stage, title, value, columns[stage], y,
                                       accent_color=accent)
                self._scene.addItem(placed[key])
        self._nodes = placed

        drawn: set[tuple[str, str]] = set()
        for machine, artifact, target, source, *_rest in rows:
            edge_color = ARTIFACT_COLORS.get(source, "#8a8a8a")
            for left_key, right_key in (
                (("machine", machine), ("artifact", artifact)),
                (("artifact", artifact), ("target", target)),
            ):
                if left_key in placed and right_key in placed:
                    pair = (left_key[1], right_key[1])
                    if pair in drawn:
                        continue
                    drawn.add(pair)
                    self._scene.addItem(EdgeItem(placed[left_key], placed[right_key],
                                                 color=edge_color))

        if activate:
            for node in placed.values():
                node.set_active(True)

        content_w = 3 * NODE_W + 2 * COL_GAP
        content_h = max(1, len(rows)) * (NODE_H + ROW_GAP) - ROW_GAP
        top = CAPTION_Y - 18
        self._scene.setSceneRect(
            QRectF(-MARGIN, top, content_w + 2 * MARGIN,
                   content_h + MARGIN - top))

    def _grid_columns(self) -> int:
        try:
            width = self.viewport().size().width()
        except (AttributeError, RuntimeError):
            width = 0
        if width < 64:
            return max(1, self._cols)
        return max(1, int(width // (CARD_W + CARD_GAP)))

    def _rebuild_overview_cards(self) -> None:
        """Infinite-canvas overview: cluster cards in a responsive grid,
        grouped under per-machine section headers.

        Every cluster gets its own coordinates -- nodes are never stacked on
        one vertical line and never overlap, regardless of dataset size.
        """
        chains, chain_sources = self._all_chains()
        clusters = self._clusters(chains, chain_sources)
        total_chains = len(chains)
        total_events = len(self._records)
        self._overview_counts = (len(clusters), total_chains, total_events)
        self._add_caption(
            f"Overview \u2014 {len(clusters)} clusters \u00b7 "
            f"{total_chains:,} chains \u00b7 {total_events:,} events "
            f"\u2014 click a card to drill into its chains")

        groups: dict[str, list[dict]] = {}
        for cluster in clusters:
            groups.setdefault(cluster["machine"], []).append(cluster)

        cols = self._grid_columns()
        self._cols = cols
        y = MARGIN
        for machine, members in groups.items():
            header = QGraphicsSimpleTextItem(
                f"\u25b8 {machine} \u00b7 {len(members)} artifacts")
            header.setBrush(QBrush(QColor("#e0e0e0")))
            font = QFont("Segoe UI", 10, QFont.Weight.DemiBold)
            header.setFont(font)
            header.setPos(0, y)
            header.setZValue(1)
            self._scene.addItem(header)
            y += 30
            for i, cluster in enumerate(members):
                row, col = divmod(i, cols)
                x = col * (CARD_W + CARD_GAP)
                yy = y + row * (CARD_H + CARD_GAP)
                card = CardItem((cluster["machine"], cluster["artifact"]),
                                cluster, x, yy)
                self._scene.addItem(card)
                self._cards.append(card)
            rows_used = max(1, -(-len(members) // cols))
            y += rows_used * (CARD_H + CARD_GAP) + SECTION_GAP

        content_w = max(cols * (CARD_W + CARD_GAP), 920)
        top = CAPTION_Y - 18
        self._scene.setSceneRect(
            QRectF(-MARGIN, top, content_w + MARGIN, max(y, 140) - top))

    def _add_caption(self, text: str) -> None:
        caption = QGraphicsSimpleTextItem(text)
        caption.setBrush(QBrush(QColor("#8a8a8a")))
        font = QFont("Segoe UI", 9)
        font.setItalic(True)
        caption.setFont(font)
        caption.setPos(0, CAPTION_Y)
        self._scene.addItem(caption)

    def _ensure_focus_visible(self) -> None:
        rects = [node.mapToScene(node.rect()).boundingRect()
                 for node in self._nodes.values()]
        if not rects:
            return
        bounds = rects[0]
        for rect in rects[1:]:
            bounds = bounds.united(rect)
        self.ensureVisible(bounds.adjusted(-48, -36, 48, 36))

    def _try_fit(self) -> None:
        if not self._pending_fit:
            return
        if not self.isVisible():
            return
        size = self.viewport().size()
        if size.width() < 64 or size.height() < 64:
            return
        rect = self._scene.sceneRect()
        if rect.isEmpty():
            return
        self._pending_fit = False
        self.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)
        self._scale = self.transform().m11()
        self._fitted_for = QSize(size)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self._pending_fit:
            QTimer.singleShot(0, self._try_fit)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.overview_active() and self._records:
            cols = self._grid_columns()
            if cols != self._cols:
                self._rebuild()
        if (self._fitted_for is not None and not self._user_zoomed
                and not self._pending_fit
                and self.viewport().size() != self._fitted_for):
            self._pending_fit = True
            QTimer.singleShot(0, self._try_fit)

    def mousePressEvent(self, event) -> None:
        if (event.button() == Qt.MouseButton.LeftButton
                and self.overview_active()):
            item = self.itemAt(event.position().toPoint())
            card = item if isinstance(item, CardItem) else None
            self._press_item = card
            self._press_pos = event.position().toPoint()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        card = self._press_item
        pos = self._press_pos
        self._press_item = None
        self._press_pos = None
        if (card is not None and pos is not None
                and event.button() == Qt.MouseButton.LeftButton
                and self.overview_active()):
            item = self.itemAt(event.position().toPoint())
            moved = (event.position().toPoint() - pos).manhattanLength()
            if item is card and moved < 6:
                self.clusterSelected.emit(card.key)
                event.accept()
                return
        super().mouseReleaseEvent(event)

    def wheelEvent(self, event) -> None:
        delta = event.angleDelta().y()
        if delta == 0 or not self._scene.items():
            event.ignore()
            return
        factor = 1.15 if delta > 0 else 1 / 1.15
        new_scale = self._scale * factor
        if not 0.08 <= new_scale <= 14.0:
            event.accept()
            return
        self._user_zoomed = True
        position = event.position().toPoint()
        before = self.mapToScene(position)
        self.scale(factor, factor)
        self._scale = new_scale
        after = self.mapToScene(position)
        self.translate(after.x() - before.x(), after.y() - before.y())
        event.accept()

    def _zoom(self, factor: float) -> None:
        new_scale = self._scale * factor
        if not 0.08 <= new_scale <= 14.0:
            return
        self._user_zoomed = True
        self.scale(factor, factor)
        self._scale = new_scale

    def keyPressEvent(self, event) -> None:
        key = event.key()
        if key in (Qt.Key_Plus, Qt.Key_Equal):
            self._zoom(1.25)
            event.accept()
        elif key == Qt.Key_Minus:
            self._zoom(1 / 1.25)
            event.accept()
        elif key == Qt.Key_0:
            self._user_zoomed = False
            self._pending_fit = True
            self._try_fit()
            event.accept()
        else:
            super().keyPressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:
        self._user_zoomed = False
        self._pending_fit = True
        self._try_fit()
        event.accept()

    def _show_context_menu(self, pos) -> None:
        item = self.itemAt(pos)
        if not item or not isinstance(item, NodeItem):
            return
        menu = QMenu(self)
        trace_action = menu.addAction("Trace Origin")
        trace_action.triggered.connect(
            lambda: self.traceOriginRequested.emit(item))
        menu.exec(self.viewport().mapToGlobal(pos))


class GraphPage(QWidget):
    """Relationship graph plus a pager toolbar.

    The overview is an infinite scrollable card grid (no pagination); the
    pager activates only inside a drilled-down cluster with more chains
    than one page holds, and the Overview button returns to the grid.
    """

    prevRequested = Signal()
    nextRequested = Signal()
    overviewRequested = Signal()

    def __init__(self, graph: RelationshipGraphView, parent=None):
        super().__init__(parent)
        self.graph = graph
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        bar = QHBoxLayout()
        bar.setContentsMargins(12, 8, 12, 4)
        bar.setSpacing(8)
        self.overview_button = QPushButton("\u3008 Overview")
        self.overview_button.setToolTip("Back to the cluster overview grid")
        self.overview_button.clicked.connect(self.overviewRequested)
        bar.addWidget(self.overview_button)
        self.prev_button = QPushButton("\u25c0 Prev")
        self.prev_button.setToolTip("Previous graph page")
        self.prev_button.clicked.connect(self.prevRequested)
        bar.addWidget(self.prev_button)
        self.page_label = QLabel("No data")
        self.page_label.setObjectName("mutedLabel")
        self.page_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bar.addWidget(self.page_label, 1)
        self.next_button = QPushButton("Next \u25b6")
        self.next_button.setToolTip("Next graph page")
        self.next_button.clicked.connect(self.nextRequested)
        bar.addWidget(self.next_button)
        root.addLayout(bar)
        root.addWidget(graph, 1)

    def refresh(self) -> None:
        self.page_label.setText(self.graph.page_info())
        nav = self.graph.pager_visible()
        self.prev_button.setEnabled(nav)
        self.next_button.setEnabled(nav)
        self.overview_button.setEnabled(not self.graph.overview_active())


class DensityBar(QWidget):
    """Event-density strip over the loaded time range.

    Each bar aggregates one time bucket; the tallest bucket glows orange so
    peak activity windows pop instantly. Dragging across the strip selects an
    attack window and emits rangeSelected(start, end); double-click clears it.
    Undated events are never binned (they cannot be placed on a timeline).
    """

    rangeSelected = Signal(object, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(60)
        self.setMaximumHeight(80)
        self.setToolTip("Event density over time \u2014 drag to isolate an attack "
                        "window, double-click to reset")
        self._bins: list[int] = []
        self._edges: list[datetime] = []
        self._sel: Optional[tuple[int, int]] = None
        self._drag_start: Optional[int] = None

    def set_records(self, records: list[TimelineRecord]) -> None:
        dated = sorted(r.dt for r in records if r.dt is not None)
        if len(dated) < 2:
            self._bins, self._edges = [], []
            self._sel = None
            self.update()
            return
        tmin, tmax = dated[0], dated[-1]
        span = (tmax - tmin).total_seconds() or 1.0
        self._edges = [tmin + timedelta(seconds=span * i / HEATMAP_BINS)
                       for i in range(HEATMAP_BINS + 1)]
        counts = [0] * HEATMAP_BINS
        for moment in dated:
            idx = min(int((moment - tmin).total_seconds() / span * HEATMAP_BINS),
                      HEATMAP_BINS - 1)
            counts[idx] += 1
        self._bins = counts
        self._sel = None
        self.update()

    def set_selection(self, start: Optional[datetime],
                      end: Optional[datetime]) -> None:
        """Mirror an externally chosen window (no signal emitted).

        Half-open windows are supported: a missing bound extends to the
        loaded range instead of clearing the overlay.
        """
        if not self._edges or (start is None and end is None):
            self._sel = None
        else:
            lo_edge = start or self._edges[0]
            hi_edge = end or self._edges[-1]
            lo = next((i for i, e in enumerate(self._edges) if e >= lo_edge),
                      len(self._edges) - 1)
            hi = next((i for i, e in enumerate(self._edges) if e > hi_edge),
                      len(self._edges)) - 1
            lo = max(0, min(lo, HEATMAP_BINS - 1))
            hi = max(lo, min(hi, HEATMAP_BINS - 1))
            self._sel = (lo, hi)
        self.update()

    def _bin_at(self, x: int) -> int:
        w = max(1, self.width())
        return max(0, min(int(x / w * HEATMAP_BINS), HEATMAP_BINS - 1))

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self._edges:
            self._drag_start = self._bin_at(event.position().toPoint().x())
            self._sel = (self._drag_start, self._drag_start)
            self.update()
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._drag_start is not None and self._edges:
            cur = self._bin_at(event.position().toPoint().x())
            self._sel = (min(self._drag_start, cur), max(self._drag_start, cur))
            self.update()
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if self._drag_start is not None and self._sel is not None and self._edges:
            lo, hi = self._sel
            if hi > lo:
                self.rangeSelected.emit(self._edges[lo], self._edges[hi + 1])
            else:
                self._sel = None
                self.update()
            self._drag_start = None
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        self._sel = None
        self._drag_start = None
        self.update()
        self.rangeSelected.emit(None, None)
        event.accept()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.fillRect(self.rect(), QColor("#121212"))
        if not self._bins:
            painter.setPen(QColor("#6d6d6d"))
            painter.setFont(QFont("Segoe UI", 8))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                             "No dated events to chart")
            return
        pad_l, pad_r, pad_t, pad_b = 6, 6, 6, 6
        w = self.width() - pad_l - pad_r
        h = self.height() - pad_t - pad_b
        peak = max(self._bins) or 1
        bw = w / HEATMAP_BINS
        for i, count in enumerate(self._bins):
            if not count:
                continue
            bh = max(2.0, h * count / peak)
            x = pad_l + i * bw + 1
            y = pad_t + h - bh
            if count == peak:
                painter.setBrush(QColor("#f0883e"))
            else:
                alpha = 90 + int(120 * count / peak)
                color = QColor("#22d3ee")
                color.setAlpha(alpha)
                painter.setBrush(color)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRect(QRectF(x, y, max(1.0, bw - 2), bh).toRect())
        if self._sel is not None:
            lo, hi = self._sel
            x0, x1 = pad_l + lo * bw, pad_l + (hi + 1) * bw
            dim = QColor("#000000")
            dim.setAlpha(140)
            painter.fillRect(QRectF(0, 0, x0, self.height()).toRect(), dim)
            painter.fillRect(QRectF(x1, 0, self.width() - x1, self.height()).toRect(), dim)
            painter.setPen(QPen(QColor("#22d3ee"), 1.5))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRect(QRectF(x0, 2, x1 - x0, self.height() - 4).toRect())


class ControlPanel(QWidget):
    openRequested = Signal()
    filterChanged = Signal(str)
    exportRequested = Signal()
    aiAnalysisRequested = Signal()
    analysisRequested = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("controlPanel")
        self.setMinimumWidth(270)
        self.setMaximumWidth(520)

        # Scrollable content: the panel grew taller than small windows, which
        # made widgets paint over each other. The stats line stays pinned.
        inner = QWidget()
        root = QVBoxLayout(inner)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(8)

        title = QLabel("Timeline Controls")
        title.setObjectName("panelTitle")
        root.addWidget(title)

        self.open_button = QPushButton("Open Timeline JSON\u2026")
        self.open_button.setObjectName("primaryButton")
        self.open_button.clicked.connect(self.openRequested)
        root.addWidget(self.open_button)

        self.export_button = QPushButton("Export Report \u2026")
        self.export_button.clicked.connect(self.exportRequested)
        root.addWidget(self.export_button)

        self.ai_button = QPushButton("AI Analysis \u2026")
        self.ai_button.clicked.connect(self.aiAnalysisRequested)
        root.addWidget(self.ai_button)

        file_caption = QLabel("Timeline file")
        file_caption.setObjectName("mutedLabel")
        root.addWidget(file_caption)

        self.path_label = QLabel("No file loaded")
        self.path_label.setObjectName("pathLabel")
        self.path_label.setWordWrap(True)
        self.path_label.setMinimumHeight(48)
        root.addWidget(self.path_label)

        search_caption = QLabel("Search / pivot")
        search_caption.setObjectName("mutedLabel")
        root.addWidget(search_caption)

        search_row = QHBoxLayout()
        search_row.setSpacing(4)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            "target path, machine, artifact file, event type\u2026")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self.filterChanged)
        search_row.addWidget(self.search_input, 1)
        self.regex_toggle = QToolButton()
        self.regex_toggle.setText(".*")
        self.regex_toggle.setCheckable(True)
        self.regex_toggle.setObjectName("regexToggle")
        self.regex_toggle.toggled.connect(
            lambda _checked: self.filterChanged.emit(self.search_input.text()))
        search_row.addWidget(self.regex_toggle)
        root.addLayout(search_row)

        source_caption = QLabel("Source filter")
        source_caption.setObjectName("mutedLabel")
        root.addWidget(source_caption)

        self.source_combo = QComboBox()
        self.source_combo.addItem("All sources", None)
        self.source_combo.currentIndexChanged.connect(
            lambda _index: self.filterChanged.emit(self.search_input.text()))
        root.addWidget(self.source_combo)

        time_caption = QLabel("Attack window (time range)")
        time_caption.setObjectName("mutedLabel")
        root.addWidget(time_caption)

        self.start_datetime = QDateTimeEdit()
        self.start_datetime.setCalendarPopup(True)
        self.start_datetime.setDateTime(
            QDateTime(2000, 1, 1, 0, 0, 0, 0, Qt.TimeSpec.UTC))
        self.start_datetime.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.start_datetime.dateTimeChanged.connect(
            lambda _dt: self.filterChanged.emit(self.search_input.text()))
        root.addWidget(self.start_datetime)

        self.end_datetime = QDateTimeEdit()
        self.end_datetime.setCalendarPopup(True)
        self.end_datetime.setDateTime(
            QDateTime(2100, 1, 1, 0, 0, 0, 0, Qt.TimeSpec.UTC))
        self.end_datetime.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.end_datetime.dateTimeChanged.connect(
            lambda _dt: self.filterChanged.emit(self.search_input.text()))
        root.addWidget(self.end_datetime)

        threat_caption = QLabel("Threat triage")
        threat_caption.setObjectName("mutedLabel")
        root.addWidget(threat_caption)

        self.threat_toggle = QToolButton()
        self.threat_toggle.setText("High Risk Only")
        self.threat_toggle.setCheckable(True)
        self.threat_toggle.setObjectName("threatToggle")
        self.threat_toggle.toggled.connect(
            lambda _checked: self.filterChanged.emit(self.search_input.text()))
        root.addWidget(self.threat_toggle)

        ingestion_caption = QLabel("Displayed sources (filter)")
        ingestion_caption.setObjectName("mutedLabel")
        ingestion_caption.setToolTip(
            "Filters which already-loaded records are VISIBLE in the "
            "timeline. These do not run acquisition — use the Tier 1 "
            "Acquisition checkboxes below for that.")
        root.addWidget(ingestion_caption)

        self.ingest_executions = QCheckBox("Executions (Prefetch, UserAssist, BAM)")
        self.ingest_executions.setChecked(True)
        self.ingest_executions.toggled.connect(
            lambda: self.filterChanged.emit(""))
        root.addWidget(self.ingest_executions)

        self.ingest_loaded = QCheckBox("Loaded Files (LNK, JumpLists, Amcache)")
        self.ingest_loaded.setChecked(True)
        self.ingest_loaded.toggled.connect(
            lambda: self.filterChanged.emit(""))
        root.addWidget(self.ingest_loaded)

        self.ingest_metadata = QCheckBox(
            "Metadata (Shellbag, RecentDocs, RunMRU)")
        self.ingest_metadata.setChecked(True)
        self.ingest_metadata.toggled.connect(
            lambda: self.filterChanged.emit(""))
        root.addWidget(self.ingest_metadata)

        self.ingest_bin = QCheckBox("Recycle Bin Items")
        self.ingest_bin.setChecked(True)
        self.ingest_bin.toggled.connect(
            lambda: self.filterChanged.emit(""))
        root.addWidget(self.ingest_bin)

        acq_caption = QLabel("Tier 1 Acquisition (Run Analysis)")
        acq_caption.setObjectName("mutedLabel")
        acq_caption.setToolTip(
            "Tick the artifacts you want the Run Analysis button to "
            "acquire from the evidence root / live host.")
        root.addWidget(acq_caption)

        self.acquire_checks: dict[str, QCheckBox] = {}
        if _TIER1_AVAILABLE:
            for item in TIER1_ARTIFACTS:
                box = QCheckBox(item["label"])
                box.setChecked(True)
                if item.get("needs_regipy"):
                    try:
                        import regipy  # noqa: F401
                    except ImportError:
                        box.setToolTip("needs: pip install regipy")
                root.addWidget(box)
                self.acquire_checks[item["id"]] = box
        else:
            missing = QLabel("tier1_artifacts.py missing \u2014 acquisition disabled")
            missing.setObjectName("mutedLabel")
            missing.setWordWrap(True)
            root.addWidget(missing)

        root_row = QHBoxLayout()
        root_row.setSpacing(4)
        self.evidence_input = QLineEdit()
        self.evidence_input.setPlaceholderText("Evidence root (empty = live host)")
        self.evidence_input.setToolTip(
            "Offline image / triage folder with Windows + Users layout. "
            "Leave empty to acquire from this machine.")
        root_row.addWidget(self.evidence_input, 1)
        self.evidence_browse = QPushButton("\u2026")
        self.evidence_browse.setFixedWidth(34)
        self.evidence_browse.setToolTip("Browse for evidence root")
        self.evidence_browse.clicked.connect(self._browse_evidence_root)
        root_row.addWidget(self.evidence_browse)
        root.addLayout(root_row)

        self.acquire_button = QPushButton("Run Analysis")
        self.acquire_button.setToolTip(
            "Acquire the checked Tier 1 artifacts and merge them into "
            "the timeline")
        self.acquire_button.clicked.connect(
            lambda: self.analysisRequested.emit(self.selected_artifacts()))
        self.acquire_button.setEnabled(bool(self.acquire_checks))
        root.addWidget(self.acquire_button)

        self.acquire_status = QLabel("")
        self.acquire_status.setObjectName("mutedLabel")
        self.acquire_status.setWordWrap(True)
        root.addWidget(self.acquire_status)

        root.addStretch(1)

        self.stats_label = QLabel("0 events")
        self.stats_label.setObjectName("mutedLabel")

        scroll = QScrollArea()
        scroll.setWidget(inner)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        stats_holder = QWidget()
        stats_layout = QHBoxLayout(stats_holder)
        stats_layout.setContentsMargins(14, 8, 14, 14)
        stats_layout.addWidget(self.stats_label, 1)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(scroll, 1)
        outer.addWidget(stats_holder)

    def search_text(self) -> str:
        return self.search_input.text()

    def selected_artifacts(self) -> list[str]:
        return [aid for aid, box in self.acquire_checks.items() if box.isChecked()]

    def set_acquire_status(self, text: str) -> None:
        self.acquire_status.setText(text)

    def _browse_evidence_root(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self, "Select evidence root", self.evidence_input.text() or str(Path.home()))
        if folder:
            self.evidence_input.setText(folder)

    def source_text(self) -> Optional[str]:
        data = self.source_combo.currentData()
        return data if isinstance(data, str) else None

    def regex_enabled(self) -> bool:
        return self.regex_toggle.isChecked()

    def threat_high_only(self) -> bool:
        return self.threat_toggle.isChecked()

    def time_range(self) -> tuple[Optional[datetime], Optional[datetime]]:
        start_dt = self.start_datetime.dateTime()
        end_dt = self.end_datetime.dateTime()
        start = (start_dt.toPython().replace(tzinfo=timezone.utc)
                 if start_dt.date().year() > 2000 else None)
        end = (end_dt.toPython().replace(tzinfo=timezone.utc)
               if end_dt.date().year() < 2100 else None)
        return (start, end)

    def ingestion_filters(self) -> dict[str, bool]:
        return {
            "executions": self.ingest_executions.isChecked(),
            "loaded_files": self.ingest_loaded.isChecked(),
            "metadata": self.ingest_metadata.isChecked(),
            "bin_items": self.ingest_bin.isChecked(),
        }

    def set_sources(self, sources: list[str]) -> None:
        current = self.source_text()
        blocked = self.source_combo.blockSignals(True)
        try:
            self.source_combo.clear()
            self.source_combo.addItem("All sources", None)
            for source in sources:
                self.source_combo.addItem(f"{source} only", source)
            if current in sources:
                self.source_combo.setCurrentIndex(sources.index(current) + 1)
        finally:
            self.source_combo.blockSignals(blocked)

    def set_file_info(self, path: str, total: int, meta: dict[str, Any],
                      tooltip: Optional[str] = None) -> None:
        self.path_label.setText(path)
        self.path_label.setToolTip(tooltip or path)
        parts = [f"{total:,} events"]
        if meta.get("skipped"):
            parts.append(f"{meta['skipped']} skipped files")
        if meta.get("dropped"):
            parts.append(f"{meta['dropped']} malformed entries")
        if meta.get("failed"):
            parts.append(f"{len(meta['failed'])} file(s) failed")
        self.stats_label.setText("  \u00b7  ".join(parts))

    def set_stats(self, shown: int, total: int) -> None:
        self.stats_label.setText(f"{shown:,} / {total:,} events")


class TraceOriginDialog(QDialog):
    def __init__(self, record: TimelineRecord,
                 related: list[TimelineRecord], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Trace Origin \u2014 Reverse Execution Chain")
        self.setMinimumSize(720, 480)

        layout = QVBoxLayout(self)

        header = QLabel(
            f"<b>Origin:</b> {record.artifact_name}<br>"
            f"<b>Target:</b> {record.target_path}<br>"
            f"<b>Related events:</b> {len(related)}")
        header.setWordWrap(True)
        layout.addWidget(header)

        tree = QTreeWidget()
        tree.setColumnCount(4)
        tree.setHeaderLabels(["Timestamp", "Source", "Event", "Artifact / Target"])
        tree.setAlternatingRowColors(True)
        tree.setRootIsDecorated(False)
        tree.setUniformRowHeights(True)
        for rec in related:
            item = QTreeWidgetItem(tree, [
                rec.timestamp,
                rec.artifact_source,
                rec.event_type,
                f"{rec.artifact_name} \u2192 {rec.target_path}",
            ])
            color = ARTIFACT_COLORS.get(rec.artifact_source, "#8a8a8a")
            item.setForeground(1, QColor(color))
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        tree.setColumnWidth(0, 200)
        tree.setColumnWidth(1, 90)
        tree.setColumnWidth(2, 120)
        layout.addWidget(tree)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1440, 900)
        self.setMinimumSize(1080, 620)

        self.records: list[TimelineRecord] = []
        self.shown: list[TimelineRecord] = []
        self.meta: dict[str, Any] = {}
        self._selected: Optional[TimelineRecord] = None
        self._last_dir = str(Path.home())
        self._bookmarked_only = False
        self._known_hashes: set[str] = set()
        self._threat_engine = ThreatEngine()
        self._threat_map: dict[int, list[ThreatMatch]] = {}
        self._ai_worker: Optional[AIAnalysisWorker] = None

        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(200)
        self._filter_timer.timeout.connect(self._apply_filter)

        self._focus_timer = QTimer(self)
        self._focus_timer.setSingleShot(True)
        self._focus_timer.setInterval(150)
        self._focus_timer.timeout.connect(self._apply_focus)

        self.controls = ControlPanel()
        self.controls.openRequested.connect(self.open_file)
        self.controls.filterChanged.connect(self._queue_filter)
        self.controls.exportRequested.connect(self._export_report)
        self.controls.aiAnalysisRequested.connect(self._run_ai_analysis)
        self.controls.analysisRequested.connect(self._run_acquisition)
        self.controls.source_combo.currentIndexChanged.connect(
            self._on_source_combo)

        self.table = TimelineTable()
        self.master_timeline = MasterTimelinePanel()
        self.bookmarks_table = TimelineTable()
        self.inspector = InspectorPanel()
        self.graph = RelationshipGraphView()
        self.graph_page = GraphPage(self.graph)
        self.graph_page.prevRequested.connect(self._on_graph_prev)
        self.graph_page.nextRequested.connect(self._on_graph_next)
        self.graph_page.overviewRequested.connect(self._on_graph_overview)
        self.graph.clusterSelected.connect(self._on_graph_cluster)
        self.shell_explorer = ShellbagsExplorer()

        self.sub_executions = ArtifactSubView()
        self.sub_loaded = ArtifactSubView()
        self.sub_metadata = ArtifactSubView()
        self.sub_bin = ArtifactSubView()

        self.tabs = QTabWidget()
        self.tabs.addTab(self.master_timeline, "Master Timeline")
        self.tabs.addTab(self.table, "Timeline Table")
        self.bookmarks_tab_index = self.tabs.addTab(
            self.bookmarks_table, "Bookmarks (0)")
        self.tabs.addTab(self.sub_executions, "Executions")
        self.tabs.addTab(self.sub_loaded, "Loaded Files")
        self.tabs.addTab(self.sub_metadata, "Metadata")
        self.tabs.addTab(self.sub_bin, "Bin Items")
        self.tabs.addTab(self.shell_explorer, "Shellbags Explorer")
        self.tabs.addTab(self.inspector, "Event Inspector")
        self.tabs.addTab(self.graph_page, "Artifact Relationship Graph")

        heat_wrap = QWidget()
        heat_layout = QVBoxLayout(heat_wrap)
        heat_layout.setContentsMargins(12, 8, 12, 2)
        heat_layout.setSpacing(2)
        self.heatmap_caption = QLabel("Event density")
        self.heatmap_caption.setObjectName("heatmapCaption")
        heat_layout.addWidget(self.heatmap_caption)
        self.heatmap = DensityBar()
        self.heatmap.rangeSelected.connect(self._on_heatmap_range)
        heat_layout.addWidget(self.heatmap)

        pill_wrap = QWidget()
        self.pill_bar = QHBoxLayout(pill_wrap)
        self.pill_bar.setContentsMargins(12, 4, 12, 6)
        self.pill_bar.setSpacing(6)
        self.pill_bar.addStretch(1)
        self.pill_group = QButtonGroup(self)
        self.pill_group.setExclusive(True)
        self.pill_group.buttonClicked.connect(self._on_pill_clicked)
        self._pills: dict[str, QPushButton] = {}
        self._set_pills([], {}, 0)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        right_layout.addWidget(heat_wrap)
        right_layout.addWidget(pill_wrap)
        right_layout.addWidget(self.tabs, 1)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.controls)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([330, 1110])
        splitter.setChildrenCollapsible(False)

        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(splitter)
        self.setCentralWidget(central)

        status = QStatusBar()
        self.setStatusBar(status)
        status.showMessage("Open a timeline JSON to begin.")

        self.table.recordSelected.connect(self._on_record_selected)
        self.master_timeline.recordSelected.connect(self._on_record_selected)
        self.bookmarks_table.recordSelected.connect(self._on_record_selected)
        self.table.bookmarkToggled.connect(self._on_bookmark_toggled)
        self.master_timeline.bookmarkToggled.connect(self._on_bookmark_toggled)
        self.bookmarks_table.bookmarkToggled.connect(self._on_bookmark_toggled)
        self.master_timeline.traceOriginRequested.connect(self._trace_origin)
        self.graph.traceOriginRequested.connect(self._trace_origin_from_node)

        open_action = QAction("Open timeline\u2026", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self.open_file)
        self.addAction(open_action)

        search_action = QAction("Focus search", self)
        search_action.setShortcut(QKeySequence.StandardKey.Find)
        search_action.triggered.connect(self._focus_search)
        self.addAction(search_action)

        export_action = QAction("Export report\u2026", self)
        export_action.setShortcut(QKeySequence("Ctrl+E"))
        export_action.triggered.connect(self._export_report)
        self.addAction(export_action)

        bookmark_action = QAction("Bookmark selected event", self)
        bookmark_action.setShortcut(QKeySequence("Ctrl+B"))
        bookmark_action.triggered.connect(self._bookmark_selected)
        self.addAction(bookmark_action)

        ai_action = QAction("AI analysis\u2026", self)
        ai_action.setShortcut(QKeySequence("Ctrl+Shift+A"))
        ai_action.triggered.connect(self._run_ai_analysis)
        self.addAction(ai_action)

    def _focus_search(self) -> None:
        self.controls.search_input.setFocus()
        self.controls.search_input.selectAll()

    # -- quick filter pills -------------------------------------------------
    @staticmethod
    def _pill_style(color: str) -> str:
        return (
            "QPushButton { background: #1e1e1e; border: 1px solid COLOR; "
            "border-radius: 12px; padding: 5px 14px; font-weight: 600; color: COLOR; }"
            "QPushButton:hover:!checked { background: #2d2d2d; }"
            "QPushButton:checked { background: COLOR; border-color: COLOR; "
            "color: #111111; }"
        ).replace("COLOR", color)

    def _set_pills(self, sources: list[str], counts: dict[str, int],
                   n_bookmarked: int) -> None:
        while self.pill_bar.count() > 1:
            item = self.pill_bar.takeAt(0)
            widget = item.widget()
            if widget is not None:
                self.pill_group.removeButton(widget)
                widget.deleteLater()
        self._pills = {}

        def add_pill(text: str, key: str, color: str) -> QPushButton:
            button = QPushButton(text)
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setStyleSheet(self._pill_style(color))
            button.setProperty("pill_key", key)
            self.pill_group.addButton(button)
            self.pill_bar.insertWidget(self.pill_bar.count() - 1, button)
            self._pills[key] = button
            return button

        add_pill("All", "__all__", "#22d3ee").setChecked(True)
        for source in sources:
            color = ARTIFACT_COLORS.get(source, "#8a8a8a")
            add_pill(f"{source} ({counts.get(source, 0):,})", source, color)
        add_pill(f"\u2605 Bookmarked ({n_bookmarked})", "__bookmarked__", "#f0883e")

    def _refresh_pill_counts(self) -> None:
        counts: dict[str, int] = {}
        n_bookmarked = 0
        for record in self.records:
            counts[record.artifact_source] = counts.get(record.artifact_source, 0) + 1
            if record.bookmarked:
                n_bookmarked += 1
        for key, button in self._pills.items():
            if key == "__all__":
                button.setText("All")
            elif key == "__bookmarked__":
                button.setText(f"\u2605 Bookmarked ({n_bookmarked})")
            else:
                button.setText(f"{key} ({counts.get(key, 0):,})")
        self.tabs.setTabText(self.bookmarks_tab_index, f"Bookmarks ({n_bookmarked})")

    def _on_pill_clicked(self, button: QPushButton) -> None:
        key = button.property("pill_key")
        blocked = self.controls.source_combo.blockSignals(True)
        try:
            if key == "__bookmarked__":
                self._bookmarked_only = True
                self.controls.source_combo.setCurrentIndex(0)
            else:
                self._bookmarked_only = False
                if key == "__all__":
                    self.controls.source_combo.setCurrentIndex(0)
                else:
                    for i in range(self.controls.source_combo.count()):
                        if self.controls.source_combo.itemData(i) == key:
                            self.controls.source_combo.setCurrentIndex(i)
                            break
        finally:
            self.controls.source_combo.blockSignals(blocked)
        self._apply_filter()

    def _on_source_combo(self, _index: int) -> None:
        self._bookmarked_only = False
        source = self.controls.source_text()
        key = source if source is not None else "__all__"
        button = self._pills.get(key)
        if button is not None and not button.isChecked():
            blocked = self.pill_group.blockSignals(True)
            try:
                button.setChecked(True)
            finally:
                self.pill_group.blockSignals(blocked)

    # -- bookmarks ------------------------------------------------------------
    def _on_bookmark_toggled(self, record) -> None:
        if not isinstance(record, TimelineRecord):
            return
        record.bookmarked = not record.bookmarked
        self._refresh_pill_counts()
        self._apply_filter(update_graph=False)

    def _bookmark_selected(self) -> None:
        if isinstance(self._selected, TimelineRecord):
            self._on_bookmark_toggled(self._selected)

    # -- heatmap attack-window --------------------------------------------------
    @staticmethod
    def _to_qdatetime(moment: datetime) -> QDateTime:
        naive = moment.replace(tzinfo=None) if moment.tzinfo else moment
        return QDateTime(naive.year, naive.month, naive.day,
                         naive.hour, naive.minute, naive.second)

    def _on_heatmap_range(self, start, end) -> None:
        blocked_start = self.controls.start_datetime.blockSignals(True)
        blocked_end = self.controls.end_datetime.blockSignals(True)
        try:
            if start is None or end is None:
                self.controls.start_datetime.setDateTime(QDateTime(2000, 1, 1, 0, 0, 0))
                self.controls.end_datetime.setDateTime(QDateTime(2100, 1, 1, 0, 0, 0))
            else:
                aware_start = start if start.tzinfo else start.replace(tzinfo=timezone.utc)
                aware_end = end if end.tzinfo else end.replace(tzinfo=timezone.utc)
                self.controls.start_datetime.setDateTime(self._to_qdatetime(aware_start))
                self.controls.end_datetime.setDateTime(self._to_qdatetime(aware_end))
        finally:
            self.controls.start_datetime.blockSignals(blocked_start)
            self.controls.end_datetime.blockSignals(blocked_end)
        self._apply_filter()

    # -- graph pager ------------------------------------------------------------
    def _refresh_graph_page(self) -> None:
        self.graph_page.refresh()

    def _on_graph_prev(self) -> None:
        if self.graph.prev_page():
            self.graph_page.refresh()

    def _on_graph_next(self) -> None:
        if self.graph.next_page():
            self.graph_page.refresh()

    def _on_graph_cluster(self, key) -> None:
        machine, artifact = str(key[0]), str(key[1])
        self.graph.focus_cluster((machine, artifact))
        self.graph_page.refresh()
        rows = self.graph._cluster_chain_rows((machine, artifact))
        events = sum(1 for r in self.shown
                     if (r.machine_id, r.artifact_name) == (machine, artifact))
        self.statusBar().showMessage(
            f"Cluster \u2014 {artifact} on {machine} \u00b7 "
            f"{len(rows):,} chains, {events:,} events in current filter")

    def _on_graph_overview(self) -> None:
        self.graph.show_overview()
        self.graph_page.refresh()
        self.statusBar().showMessage(
            f"Cluster overview \u2014 {len(self.shown):,} events in current filter")

    def _filter_summary(self) -> str:
        parts = []
        source = self.controls.source_text()
        parts.append(f"Source: {source}" if source else "Source: all")
        query = self.controls.search_text().strip()
        if query:
            mode = "regex" if self.controls.regex_enabled() else "text"
            parts.append(f"Search ({mode}): {query}")
        start_dt, end_dt = self.controls.time_range()
        if start_dt or end_dt:
            parts.append(f"Window: {start_dt or '...'} \u2192 {end_dt or '...'}")
        if self._bookmarked_only:
            parts.append("Bookmarked only")
        if self.controls.threat_high_only():
            parts.append("High-risk threats only")
        if len(self.shown) != len(self.records):
            parts.append(f"Filtered {len(self.shown):,} of {len(self.records):,}")
        return " \u00b7 ".join(parts)

    def open_file(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Open timeline JSON (select several to merge)", self._last_dir,
            "Timeline JSON (*.json);;All files (*)")
        if paths:
            self.load_paths(paths)

    def load_path(self, path: str) -> None:
        self.load_paths([path])

    def load_paths(self, paths: list[str]) -> None:
        unique = list(dict.fromkeys(p for p in paths if p))
        if not unique:
            return
        records, meta = load_timelines(unique)
        failed = meta.get("failed", [])
        if failed:
            details = "\n".join(
                f"\u2022 {Path(item['file']).name}: {item['error']}" for item in failed)
            if records:
                QMessageBox.warning(
                    self, "Some timelines could not be loaded",
                    "Loaded the remaining file(s), but skipped:\n\n" + details)
            else:
                QMessageBox.critical(
                    self, "Load failed",
                    "None of the selected files could be loaded:\n\n" + details)
                return

        self.records = records
        self.meta = meta
        self._selected = None
        self._bookmarked_only = False
        try:
            from tier1_artifacts import identity_of_timeline_record
            for record in records:
                try:
                    self._known_hashes.add(identity_of_timeline_record(record))
                except Exception:
                    continue
        except ImportError:
            pass
        self._last_dir = str(Path(unique[0]).parent)
        blocked = self.controls.search_input.blockSignals(True)
        self.controls.search_input.clear()
        self.controls.search_input.blockSignals(blocked)
        self.controls.set_sources(sorted({r.artifact_source for r in records}))
        self._set_pills(sorted({r.artifact_source for r in records}),
                        meta.get("by_source", {}), 0)
        self.tabs.setTabText(self.bookmarks_tab_index, "Bookmarks (0)")
        self.heatmap.set_records(records)
        dated = sum(1 for r in records if r.dt is not None)
        self.heatmap_caption.setText(
            f"Event density \u00b7 {dated:,} dated of {len(records):,} events")
        loaded = meta.get("paths", [])
        if len(loaded) > 1:
            display = (f"{len(loaded)} files: "
                       + ", ".join(Path(p).name for p in loaded))
            tooltip = "\n".join(loaded)
        else:
            display = loaded[0] if loaded else unique[0]
            tooltip = display
        self.controls.set_file_info(display, len(records), meta, tooltip=tooltip)
        self.inspector.clear()
        self._compute_threats()
        self._apply_filter()

        by_source = meta.get("by_source", {})
        if len(loaded) > 1:
            breakdown = ", ".join(
                f"{count:,} {source}" for source, count in sorted(by_source.items()))
            message = (f"Loaded {len(records):,} events from {len(loaded)} files"
                       + (f" ({breakdown})" if breakdown else ""))
        elif loaded:
            message = f"Loaded {len(records):,} events from {Path(loaded[0]).name}"
        else:
            message = f"Loaded {len(records):,} events"
        if meta.get("skipped"):
            message += f" \u00b7 {meta['skipped']} skipped files"
        if meta.get("dropped"):
            message += f" \u00b7 {meta['dropped']} malformed entries dropped"
        if failed:
            message += f" \u00b7 {len(failed)} file(s) failed"
        self.statusBar().showMessage(message)

    def _compute_threats(self) -> None:
        self._threat_map = {}
        for record in self.records:
            matches = self._threat_engine.analyze(record)
            if matches:
                self._threat_map[id(record)] = matches

    def _sync_source_widgets(self) -> None:
        """Refresh source dropdown, pills, heatmap and bookmark tab title."""
        sources = sorted({r.artifact_source for r in self.records})
        self.controls.set_sources(sources)
        counts: dict[str, int] = {}
        n_bookmarked = 0
        for record in self.records:
            counts[record.artifact_source] = counts.get(record.artifact_source, 0) + 1
            if record.bookmarked:
                n_bookmarked += 1
        if hasattr(self, "_pills"):
            self._set_pills(sources, counts, n_bookmarked)
        if hasattr(self, "bookmarks_tab_index"):
            self.tabs.setTabText(self.bookmarks_tab_index,
                                 f"Bookmarks ({n_bookmarked})")
        if hasattr(self, "heatmap"):
            self.heatmap.set_records(self.records)
            dated = sum(1 for r in self.records if r.dt is not None)
            self.heatmap_caption.setText(
                f"Event density \u00b7 {dated:,} dated of {len(self.records):,} events")

    def _run_acquisition(self, selected: list[str]) -> None:
        try:
            from tier1_artifacts import AcquisitionEngine
        except ImportError as exc:
            QMessageBox.critical(self, "Acquisition unavailable",
                                 f"Could not load tier1_artifacts.py:\n\n{exc}")
            return
        if not selected:
            QMessageBox.information(
                self, "Run Analysis",
                "No Tier 1 artifacts are selected.\n\n"
                "Tick at least one checkbox in the 'Tier 1 Acquisition "
                "(Run Analysis)' section of the left sidebar — e.g. "
                "Prefetch, LNK Files or Jump Lists — then click "
                "Run Analysis again.\n\n"
                "Note: the 'Displayed sources' toggles only filter which "
                "already-loaded records are visible; they do not run "
                "acquisition.")
            return
        root = self.controls.evidence_input.text().strip() or None
        if root and not Path(root).is_dir():
            QMessageBox.critical(self, "Run Analysis",
                                 f"Evidence root is not a directory:\n{root}")
            return
        self.controls.set_acquire_status("Running Tier 1 acquisition\u2026")
        QApplication.processEvents()
        engine = AcquisitionEngine(root, None)
        try:
            raws, report = engine.run(selected)
        except Exception as exc:  # noqa: BLE001 - never break the UI
            self.controls.set_acquire_status(f"Acquisition failed: {exc}")
            QMessageBox.critical(self, "Run Analysis",
                                 f"Acquisition failed:\n\n{exc}")
            return
        added = 0
        for raw in raws:
            digest = raw.get("source_hash", "")
            if digest in self._known_hashes:
                continue
            try:
                record = normalize_event(raw)
            except Exception:
                continue
            self._known_hashes.add(digest)
            self.records.append(record)
            added += 1
        self.records.sort(key=_record_sort_key)
        self._selected = None
        try:
            self._compute_threats()
        except Exception:
            pass
        self._sync_source_widgets()
        self.inspector.clear()
        self._apply_filter()
        failed = {k: v for k, v in report.items()
                  if v.get("status") in ("failed", "unavailable")}
        # an artifact that produced nothing BUT has an explanatory note
        # (locked profile skipped, no entries recovered, ...) also needs
        # the analyst's attention — unless it is just "all duplicates".
        empty_with_note = {
            k: v for k, v in report.items()
            if v.get("status") == "empty"
            and v.get("count", 0) == 0
            and v.get("note")
            and "duplicate(s) skipped" not in v.get("note", "")}
        issues = {**failed, **empty_with_note}
        parts = [f"{added:,} new events"]
        skipped_dups = len(raws) - added
        if skipped_dups:
            parts.append(f"{skipped_dups} duplicate(s) skipped")
        summary = ", ".join(parts) + f" from {len(selected)} artifact(s)"
        self.controls.set_acquire_status(summary)
        message = f"Acquired {summary}"
        if issues:
            message += f" \u00b7 {len(issues)} artifact(s) with issues"
        self.statusBar().showMessage(message)
        if issues:
            details = "\n".join(
                f"\u2022 {k}: {v.get('note') or v.get('status')}"
                for k, v in issues.items())
            QMessageBox.warning(
                self, "Acquisition finished with issues",
                f"{summary}.\n\nThe following need attention:\n\n{details}")

    def _queue_filter(self, _text: str) -> None:
        self._filter_timer.start()

    def _apply_filter(self, update_graph: bool = True) -> None:
        query = self.controls.search_text().strip()
        source = self.controls.source_text()
        use_regex = self.controls.regex_enabled()
        threat_high = self.controls.threat_high_only()
        start_dt, end_dt = self.controls.time_range()
        ingestion = self.controls.ingestion_filters()
        bookmarked_only = self._bookmarked_only

        regex_ok = True
        compiled_re: Optional[re.Pattern] = None
        if query and use_regex:
            try:
                compiled_re = re.compile(query, re.IGNORECASE)
            except re.error:
                compiled_re = None
                regex_ok = False
        self.controls.search_input.setStyleSheet(
            "" if regex_ok or not query else "border: 1px solid #f85149;")

        shown: list[TimelineRecord] = []
        for record in self.records:
            if bookmarked_only and not record.bookmarked:
                continue
            if source is not None and record.artifact_source != source:
                continue

            if start_dt is not None:
                if record.dt is None:
                    continue
                if record.dt < start_dt:
                    continue

            if end_dt is not None:
                if record.dt is None:
                    continue
                if record.dt > end_dt:
                    continue

            if query:
                if compiled_re is not None:
                    if not compiled_re.search(record.search_blob):
                        continue
                else:
                    if query.lower() not in record.search_blob:
                        continue

            if threat_high:
                threats = self._threat_map.get(id(record), [])
                if self._threat_engine.max_severity(threats) != "high":
                    continue

            if not ingestion.get("executions", True):
                if record.artifact_source in ("Prefetch", "UserAssist", "BAM"):
                    continue
            if not ingestion.get("loaded_files", True):
                if record.artifact_source in ("LNK", "JumpLists", "Amcache"):
                    continue
            if not ingestion.get("metadata", True):
                if record.artifact_source in ("Shellbag", "RecentDocs",
                                              "RegistryMRU"):
                    continue
            if not ingestion.get("bin_items", True):
                if record.artifact_source == "RecycleBin":
                    continue

            shown.append(record)

        previous = self._selected
        self.shown = shown
        self.table.populate(shown, self._threat_map)
        self.master_timeline.populate(shown, self._threat_map)
        bookmarked = [record for record in shown if record.bookmarked]
        self.bookmarks_table.populate(bookmarked, self._threat_map)
        self.shell_explorer.populate(shown)
        self.sub_executions.populate(shown, "Executions")
        self.sub_loaded.populate(shown, "Loaded Files")
        self.sub_metadata.populate(shown, "Metadata")
        self.sub_bin.populate(shown, "Bin Items")
        self.controls.set_stats(len(shown), len(self.records))
        self.heatmap.set_selection(start_dt, end_dt)

        restored: Optional[TimelineRecord] = None
        if previous is not None:
            restored = next(
                (record for record in shown if record is previous), None)

        if restored is not None:
            row = self.table.find_row(restored)
            if row >= 0:
                self.table.selectRow(row)
        else:
            self._selected = None
            self.inspector.clear()
            if update_graph:
                self.graph.set_data(shown, focus=None, refit=True)
                self.graph_page.refresh()
            if query or source is not None or start_dt or end_dt or threat_high \
                    or bookmarked_only or not all(ingestion.values()):
                message = (f"Showing {len(shown):,} of {len(self.records):,} events")
                if not regex_ok:
                    message += " \u00b7 invalid regex, matched as plain text"
                if not shown and self.records:
                    message += " \u2014 nothing matches; check source, ingestion and time filters"
                self.statusBar().showMessage(message)
            elif self.records:
                self.statusBar().showMessage(
                    f"{len(self.records):,} events loaded \u2014 select a row "
                    "to inspect its properties.")

    def _on_record_selected(self, record) -> None:
        self._selected = record if isinstance(record, TimelineRecord) else None
        if self._selected is None:
            self.inspector.clear()
            self.graph.set_data(self.shown, focus=None, refit=False)
            self.graph_page.refresh()
        else:
            self.inspector.show_record(self._selected)
            self._focus_timer.start()

    def _apply_focus(self) -> None:
        if self._selected is not None:
            self.graph.set_data(self.shown, focus=self._selected, refit=False)
            self.graph_page.refresh()
            self.statusBar().showMessage(
                f"{self._selected.artifact_source} \u00b7 "
                f"{self._selected.artifact_name} \u2192 {self._selected.target_path}")

    def _trace_origin(self, record: TimelineRecord) -> None:
        related = [
            r for r in self.records
            if r.target_path == record.target_path
            or r.artifact_name == record.artifact_name
        ]
        related.sort(key=_record_sort_key)
        dialog = TraceOriginDialog(record, related, self)
        dialog.exec()

    def _trace_origin_from_node(self, node: NodeItem) -> None:
        for record in self.records:
            if record.artifact_name == node.value or record.target_path == node.value:
                self._trace_origin(record)
                return

    def _export_report(self) -> None:
        if not self.shown:
            QMessageBox.information(
                self, "Export", "No events to export.")
            return

        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, "Export report", str(self._last_dir),
            "CSV report (*.csv);;HTML report (*.html)")

        if not file_path:
            return

        try:
            if "CSV" in selected_filter or file_path.lower().endswith(".csv"):
                if not file_path.lower().endswith(".csv"):
                    file_path += ".csv"
                _export_csv(self.shown, file_path)
                fmt = "CSV"
            else:
                if not file_path.lower().endswith(".html"):
                    file_path += ".html"
                title = f"DFIR Timeline Report ({len(self.shown):,} events)"
                _export_html(self.shown, file_path, title, self._filter_summary())
                fmt = "HTML"
        except (OSError, ValueError) as exc:
            QMessageBox.critical(
                self, "Export failed", f"Could not write report:\n\n{exc}")
            return

        self.statusBar().showMessage(
            f"Exported {len(self.shown):,} events to {fmt} \u2014 {file_path}")

        open_dir = str(Path(file_path).parent)
        self._last_dir = open_dir

    def _run_ai_analysis(self) -> None:
        if not self.shown:
            QMessageBox.information(
                self, "AI Analysis", "No events to analyze.")
            return

        settings = AISettingsDialog.get_settings()
        if not settings["api_key"]:
            dlg = AISettingsDialog(self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            settings = AISettingsDialog.get_settings()

        events_text = "\n".join(
            f"[{r.timestamp}] {r.artifact_source} | {r.event_type} | "
            f"{r.artifact_name} -> {r.target_path} | {r.machine_id}"
            for r in self.shown[:500]
        )

        prompt = (
            f"Analyze the following forensic timeline ({len(self.shown)} events) "
            f"and provide:\n"
            f"1. Executive summary of the incident\n"
            f"2. Key timeline events in chronological order\n"
            f"3. Indicators of compromise (IOCs)\n"
            f"4. Recommended next steps for the investigation\n\n"
            f"Timeline events:\n{events_text}"
        )

        self._ai_worker = AIAnalysisWorker(
            settings["api_key"], settings["endpoint"], settings["model"], prompt)
        self._ai_worker.analysisComplete.connect(self._on_ai_complete)
        self._ai_worker.analysisError.connect(self._on_ai_error)
        self._ai_worker.start()

        self.statusBar().showMessage("AI analysis in progress...")

    def _on_ai_complete(self, text: str) -> None:
        dlg = AIAnalysisDialog(text, self)
        dlg.exec()
        self.statusBar().showMessage("AI analysis complete.")

    def _on_ai_error(self, error: str) -> None:
        QMessageBox.critical(
            self, "AI Analysis Failed",
            f"The AI API returned an error:\n\n{error}")
        self.statusBar().showMessage("AI analysis failed.")


def configure_app(app: QApplication) -> QApplication:
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    app.setPalette(dark_palette())
    app.setStyleSheet(DARK_QSS)
    return app


def main(argv: Optional[list[str]] = None) -> int:
    arguments = list(sys.argv if argv is None else argv)
    app = configure_app(QApplication(arguments))

    window = MainWindow()
    window.show()
    if len(arguments) > 1:
        QTimer.singleShot(0, lambda: window.load_paths(arguments[1:]))
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
