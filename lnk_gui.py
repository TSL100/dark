#!/usr/bin/env python3
"""
lnk_gui.py - DFIR LNK Forensics GUI (final integrated version).

Merged views over the JSON produced by lnk_parser.py / lnk_forensics.py:
  * Visual Timeline  - zoomable swim-lane timeline (wheel zoom, drag pan, click select)
  * Timeline Table   - filterable, synced with every other view
  * Artifact Relationship Node Graph - Machine -> LNK File -> Target
  * JSON Inspector   - full normalized event properties

Controls: wheel = zoom, left-drag = pan, click = select.
Run:  python lnk_gui.py [lnk_timeline.json]
"""

import json
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QPointF, Qt, QTimer
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QGraphicsScene, QGraphicsView, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QSizePolicy,
    QSplitter, QStatusBar, QTabWidget, QTableWidget, QTableWidgetItem,
    QTextEdit, QVBoxLayout, QWidget,
)

EVENT_TYPES = [
    ("Target Created", "#4CAF50"),
    ("Target Accessed", "#2196F3"),
    ("Target Modified", "#FF9800"),
    ("LNK File Created", "#26A69A"),
    ("LNK File Modified", "#AB47BC"),
]
TYPE_COLOR = dict(EVENT_TYPES)
LANES = [name for name, _ in EVENT_TYPES]

EVENT_TYPE_ALIAS = {
    "Target Creation": "Target Created",
    "Target Access": "Target Accessed",
    "Target Modification": "Target Modified",
    "LNK File Created": "LNK File Created",
    "LNK File Modified": "LNK File Modified",
}


def normalize(event):
    d = event.get("details") or {}
    ts = event.get("timestamp", "N/A")
    try:
        parsed = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        parsed = None
    raw_type = (event.get("event") or event.get("timestamp_type")
                or event.get("event_type") or "LNK Event")
    return {
        "timestamp": ts,
        "event": raw_type,
        "lane": EVENT_TYPE_ALIAS.get(raw_type, "LNK File Modified"),
        "target_path": event.get("target_path", event.get("path", "N/A")),
        "machine_id": d.get("machine_id", event.get("machine_id", "N/A")),
        "lnk_file": event.get("lnk_file", d.get("lnk_file", "N/A")),
        "lnk_path": event.get("lnk_path", d.get("lnk_path", "N/A")),
        "volume_serial": d.get("volume_serial_number",
                                d.get("volume_serial", "N/A")),
        "_dt": parsed,
    }


class TimelineWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.events = []
        self.filtered = []
        self.selected = None
        self.on_select = None
        self.t0 = 0.0
        self.span = 1.0
        self.zoom = 1.0
        self.pan = 0.0
        self._hit = []
        self._drag = None
        self.setMouseTracking(True)
        self.setMinimumHeight(240)

    def set_events(self, events):
        self.events = [e for e in events if e.get("_dt")]
        if self.events:
            self.t0 = self.events[0]["_dt"].timestamp()
            self.span = max(self.events[-1]["_dt"].timestamp() - self.t0, 1.0)
        else:
            self.t0, self.span = 0.0, 1.0
        self.zoom, self.pan = 1.0, 0.0
        self.selected = None
        self.apply_filter(self.events)

    def apply_filter(self, filtered):
        self.filtered = sorted(filtered, key=lambda e: e["_dt"])
        self.update()

    def view_range(self):
        win = self.span / self.zoom
        s = self.t0 + self.pan
        return s, s + win

    def x_for(self, ts, w):
        s, e = self.view_range()
        return (ts - s) / (e - s) * w

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor("#181825"))
        if not self.filtered:
            p.setPen(QColor("#666677"))
            p.drawText(self.rect(), Qt.AlignCenter, "No events match the current filters")
            p.end()
            return

        top = 26
        lane_h = (h - top - 8) / len(LANES)
        s, e = self.view_range()
        p.setFont(QFont("Consolas", 8))

        for i, name in enumerate(LANES):
            y = top + i * lane_h
            p.setPen(QColor("#2B2B3D"))
            p.drawLine(0, int(y), w, int(y))
            p.setPen(QColor(TYPE_COLOR[name]))
            p.drawText(6, int(y + lane_h / 2 + 3), name)

        step = self._tick_step(w)
        t = self._ceil(s, step)
        while t <= e:
            x = self.x_for(t, w)
            p.setPen(QColor("#262636"))
            p.drawLine(int(x), top - 4, int(x), h)
            p.setPen(QColor("#7777AA"))
            p.drawText(int(x) + 3, 15, self._fmt_tick(t, step))
            t += step

        self._hit = []
        for event in self.filtered:
            ts = event["_dt"].timestamp()
            if ts < s or ts > e:
                continue
            x = self.x_for(ts, w)
            if x < -12 or x > w + 12:
                continue
            lane_name = event.get("lane") or event["event"]
            if lane_name not in TYPE_COLOR:
                continue
            lane = LANES.index(lane_name)
            y = top + lane * lane_h + lane_h / 2
            color = QColor(TYPE_COLOR[lane_name])
            if event is self.selected:
                p.setPen(QPen(QColor("#FFFFFF"), 2))
                p.setBrush(QBrush(color))
                p.drawEllipse(QPointF(x, y), 9, 9)
            else:
                p.setPen(Qt.NoPen)
                p.setBrush(QBrush(color))
                p.drawEllipse(QPointF(x, y), 4, 4)
            self._hit.append((x, y, event))
        p.end()

    def _tick_step(self, w):
        s, e = self.view_range()
        want = (e - s) / max(w / 110.0, 1.0)
        for step in (1, 5, 15, 30, 60, 300, 900, 1800, 3600, 10800, 21600,
                     43200, 86400, 604800, 2592000, 31536000, 63072000,
                     157680000, 315360000, 630720000):
            if step >= want:
                return step
        return 630720000

    @staticmethod
    def _ceil(t, step):
        r = t % step
        return int(t - r + step) if r else int(t)

    @staticmethod
    def _fmt_tick(t, step):
        d = datetime.fromtimestamp(t)
        if step >= 31536000:
            return d.strftime("%Y")
        if step >= 86400:
            return d.strftime("%Y-%m-%d")
        if step >= 3600:
            return d.strftime("%m-%d %H:%M")
        return d.strftime("%H:%M:%S")

    def wheelEvent(self, ev):
        f = 1.25 if ev.angleDelta().y() > 0 else 0.8
        px = ev.position().x()
        s, e = self.view_range()
        tc = s + (px / max(self.width(), 1)) * (e - s)
        self.zoom = min(max(self.zoom * f, 1.0), 1e6)
        win = self.span / self.zoom
        self.pan = min(max(tc - (px / max(self.width(), 1)) * win, 0.0),
                       max(self.span - win, 0.0))
        self.update()

    def mousePressEvent(self, ev):
        if ev.button() == Qt.LeftButton:
            self._drag = (ev.position().x(), self.pan)

    def mouseMoveEvent(self, ev):
        if self._drag is not None:
            dx = ev.position().x() - self._drag[0]
            s, e = self.view_range()
            win = e - s
            self.pan = min(max(self._drag[1] - dx * win / max(self.width(), 1), 0.0),
                           max(self.span - win, 0.0))
            self.update()

    def mouseReleaseEvent(self, ev):
        if ev.button() == Qt.LeftButton and self._drag is not None:
            moved = abs(ev.position().x() - self._drag[0])
            if moved < 4:
                self._pick(ev.position().x(), ev.position().y())
            self._drag = None

    def _pick(self, px, py):
        best, best_d = None, 12.0
        for x, y, event in self._hit:
            d = ((x - px) ** 2 + (y - py) ** 2) ** 0.5
            if d < best_d:
                best, best_d = event, d
        self.selected = best
        self.update()
        if best is not None and self.on_select:
            self.on_select(best)


class NodeGraphView(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.setBackgroundBrush(QBrush(QColor("#1e1e1e")))
        self.setMinimumHeight(220)

    def draw_node_graph(self, event):
        self.scene.clear()
        machine = str(event.get("machine_id", "Unknown Machine"))
        lnk = str(event.get("lnk_file", "Unknown LNK"))
        target = str(event.get("target_path", "Unknown Target"))
        event_type = str(event.get("event", "LNK Event"))
        ts = str(event.get("timestamp", ""))[:10]

        node_brush = QBrush(QColor("#2d2d2d"))

        def add_node(x, title, subtitle, color):
            self.scene.addEllipse(x, -50, 190, 100, QPen(QColor(color), 2), node_brush)
            t1 = self.scene.addText(title, QFont("Arial", 9, QFont.Bold))
            t1.setDefaultTextColor(QColor("white"))
            t1.setPos(x + 10, -38)
            t2 = self.scene.addText(subtitle, QFont("Arial", 8))
            t2.setDefaultTextColor(QColor("#BBBBBB"))
            t2.setPos(x + 10, -14)

        add_node(-330, "Machine ID", self._clip(machine, 24), "#4CAF50")
        add_node(-110, "LNK File", f"{self._clip(lnk, 24)}\n{event_type} | {ts}", "#2196F3")
        add_node(110, "Target Path", self._clip(target, 26), "#FF9800")

        line_pen = QPen(QColor("#888888"), 2, Qt.DashLine)
        self.scene.addLine(-140, 0, -110, 0, line_pen)
        self.scene.addLine(80, 0, 110, 0, line_pen)

        self.scene.setSceneRect(-350, -80, 670, 160)
        self.fitInView(self.scene.sceneRect(), Qt.KeepAspectRatio)

    @staticmethod
    def _clip(s, n):
        return s if len(s) <= n else "..." + s[-(n - 3):]

    def resizeEvent(self, ev):
        super().resizeEvent(ev)
        rect = self.scene.sceneRect()
        if rect.isValid() and not rect.isNull():
            self.fitInView(rect, Qt.KeepAspectRatio)


class LNKTimelineApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DFIR LNK Forensics - Timeline & Artifact Node Graph")
        self.resize(1400, 850)
        self.timeline_data = []
        self._search_text = ""
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.timeout.connect(self._apply_search)
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        top_layout = QHBoxLayout()
        self.btn_load = QPushButton("Load timeline JSON")
        self.btn_load.setStyleSheet(
            "font-weight: bold; padding: 6px; background-color: #2b5b84; color: white;")
        self.btn_load.clicked.connect(self.load_json_file)
        top_layout.addWidget(self.btn_load)

        top_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            "Filter by path, machine ID, LNK file, or event...")
        self.search_input.textChanged.connect(self._queue_search)
        top_layout.addWidget(self.search_input, 1)

        self.legend = QLabel("   ".join(
            f'<font color="{c}">&#9632;</font> {n}' for n, c in EVENT_TYPES))
        top_layout.addWidget(self.legend)

        toolbar = QWidget()
        toolbar.setLayout(top_layout)
        toolbar.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        main_layout.addWidget(toolbar)

        splitter = QSplitter(Qt.Horizontal)

        left_tabs = QTabWidget()
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["Timestamp (UTC)", "Event Type", "Target Path", "LNK File", "Machine ID"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self.on_row_selected)
        left_tabs.addTab(self.table, "Timeline Table")

        self.timeline_view = TimelineWidget()
        self.timeline_view.on_select = self._on_timeline_select
        left_tabs.addTab(self.timeline_view, "Visual Timeline")
        splitter.addWidget(left_tabs)

        right_splitter = QSplitter(Qt.Vertical)
        graph_container = QWidget()
        graph_layout = QVBoxLayout(graph_container)
        graph_layout.addWidget(
            QLabel("<b>Artifact Relationship Node Graph</b>  (Machine &rarr; LNK File &rarr; Target)"))
        self.node_view = NodeGraphView()
        graph_layout.addWidget(self.node_view)
        right_splitter.addWidget(graph_container)

        inspector_container = QWidget()
        inspector_layout = QVBoxLayout(inspector_container)
        inspector_layout.addWidget(QLabel("<b>Full Event Properties (JSON Inspector)</b>"))
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setPlaceholderText("Select an event to inspect properties...")
        inspector_layout.addWidget(self.details_text)
        right_splitter.addWidget(inspector_container)

        right_splitter.setSizes([380, 320])
        splitter.addWidget(right_splitter)
        splitter.setSizes([820, 580])
        splitter.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        main_layout.addWidget(splitter)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Wheel: zoom  |  Left-drag: pan  |  Click: select")

    def load_json_file(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Open Timeline JSON", "", "JSON Files (*.json);;All Files (*)")
        if file_name:
            self.load(file_name)

    def load(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                events = data.get("events", data.get("timeline", []))
                skipped = data.get("skipped") or []
            else:
                events = data
                skipped = []
            self.timeline_data = [normalize(e) for e in events]
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to parse JSON:\n{str(e)}")
            return
        self.setWindowTitle(f"DFIR LNK Forensics - {path}")
        self.populate_table(self.timeline_data)
        self.timeline_view.set_events(self.timeline_data)
        msg = f"Loaded {len(self.timeline_data)} events from {path}"
        if skipped:
            msg += f" | {len(skipped)} files skipped"
        self.statusBar().showMessage(msg, 5000)

    def populate_table(self, events):
        self.table.setRowCount(len(events))
        for row_idx, event in enumerate(events):
            self.table.setItem(row_idx, 0, QTableWidgetItem(str(event["timestamp"])))
            self.table.setItem(row_idx, 1, QTableWidgetItem(str(event["event"])))
            self.table.setItem(row_idx, 2, QTableWidgetItem(str(event["target_path"])))
            self.table.setItem(row_idx, 3, QTableWidgetItem(str(event["lnk_file"])))
            self.table.setItem(row_idx, 4, QTableWidgetItem(str(event["machine_id"])))
            self.table.item(row_idx, 0).setData(Qt.UserRole, event)

    def _queue_search(self, text):
        self._search_text = text
        self._search_timer.start(250)

    def _apply_search(self):
        query = self._search_text.lower()
        for row in range(self.table.rowCount()):
            match = not query
            if not match:
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    if item and query in item.text().lower():
                        match = True
                        break
            self.table.setRowHidden(row, not match)

    def on_row_selected(self):
        selected_items = self.table.selectedItems()
        if not selected_items:
            return
        row = selected_items[0].row()
        event = self.table.item(row, 0).data(Qt.UserRole)
        if event:
            self._show_event(event)

    def _on_timeline_select(self, event):
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0).data(Qt.UserRole) is event:
                self.table.selectRow(row)
                return
        self._show_event(event)

    def _show_event(self, event):
        self.timeline_view.selected = event
        self.timeline_view.update()
        self.node_view.draw_node_graph(event)
        self.details_text.setText(json.dumps(
            {k: v for k, v in event.items() if k != "_dt"}, indent=4))


def main():
    app = QApplication(sys.argv)
    window = LNKTimelineApp()
    window.show()
    if len(sys.argv) > 1 and Path(sys.argv[1]).exists():
        window.load(sys.argv[1])
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
