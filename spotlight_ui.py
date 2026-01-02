# SPDX-License-Identifier: Apache-2.0
"""
UI components for IDA Spotlight.

This module contains all UI-related classes including:
- SpotlightInspectForm: The quick inspector panel
- SpotlightViewForm: The main results view
- SpotlightKBSettingsDialog: KB configuration dialog
- SpotlightTableWidget: Custom table with Enter key handling
- Priority colors and helpers
"""

import csv
import json
from typing import Any, Callable, Dict, List, Optional

import ida_kernwin

from PySide6 import QtCore, QtGui, QtWidgets

from spotlight_utils import (
    qt_alive,
    fmt_ea,
    widget_title,
    find_code_widget_by_title,
    func_start_from_any_ea,
)
from spotlight_config import (
    kb_get_setting,
    kb_set_setting,
    kb_db_path,
    default_kb_db_path,
)
from spotlight_scanner import (
    CTX,
    ChunkedScanner,
    compute_priority_tiers,
    render_inspector,
    top_reason_str,
    categories_str,
)
from spotlight_kb import log_kb_sample_correlation


__all__ = [
    # Colors
    "priority_color",
    # Dialogs
    "SpotlightKBSettingsDialog",
    # Widgets
    "SpotlightTableWidget",
    # Forms
    "SpotlightInspectForm",
    "SpotlightViewForm",
]


# ----------------------------------------------------------------------
# Priority Colors
# ----------------------------------------------------------------------

# Priority color mapping
_PRIORITY_COLORS: Dict[str, QtGui.QColor] = {
    "critical": QtGui.QColor(255, 90, 90),
    "high": QtGui.QColor(255, 170, 70),
    "medium": QtGui.QColor(255, 235, 120),
}


def priority_color(priority: str) -> Optional[QtGui.QColor]:
    """
    Get the background color for a priority tier.

    Args:
        priority: One of "critical", "high", "medium", or "low".

    Returns:
        A QColor for the tier, or None for "low" priority.
    """
    return _PRIORITY_COLORS.get(priority)


# ----------------------------------------------------------------------
# KB Settings Dialog
# ----------------------------------------------------------------------

class SpotlightKBSettingsDialog(QtWidgets.QDialog):
    """Dialog for configuring KB database path."""

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        """
        Initialize the KB settings dialog.

        Args:
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self.setWindowTitle("IDA Spotlight – KB Settings")
        self.setMinimumWidth(650)

        # Load current path (empty => default)
        current_path = kb_get_setting("db_path", "").strip()
        self._db_edit = QtWidgets.QLineEdit(current_path)
        self._db_edit.setPlaceholderText(default_kb_db_path())

        form_layout = QtWidgets.QFormLayout()
        form_layout.addRow("KB database (SQLite):", self._db_edit)

        btn_ok = QtWidgets.QPushButton("OK")
        btn_ok.clicked.connect(self.accept)

        btn_cancel = QtWidgets.QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(btn_ok)
        button_layout.addWidget(btn_cancel)

        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.addLayout(form_layout)
        main_layout.addLayout(button_layout)

    def accept(self) -> None:
        """Save the KB path setting and close."""
        kb_set_setting("db_path", self._db_edit.text().strip())
        super().accept()


# ----------------------------------------------------------------------
# Custom Table Widget
# ----------------------------------------------------------------------

class SpotlightTableWidget(QtWidgets.QTableWidget):
    """Table widget with custom Enter key handling."""

    enter_pressed = QtCore.Signal()

    def keyPressEvent(self, event: QtGui.QKeyEvent) -> None:
        """
        Handle key press events, emitting signal on Enter/Return.

        Args:
            event: The key press event.
        """
        if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
            self.enter_pressed.emit()
            return
        super().keyPressEvent(event)


# ----------------------------------------------------------------------
# Inspect Form
# ----------------------------------------------------------------------

class SpotlightInspectForm(ida_kernwin.PluginForm):
    """
    Quick inspector panel for viewing function details.

    Can be synced to code views to automatically update
    when the cursor moves to different functions.

    Attributes:
        on_close_callback: Optional callback invoked when form closes.
    """

    # Callback to notify when form closes (set externally to avoid circular imports)
    on_close_callback: Optional[Callable[[], None]] = None

    def __init__(self) -> None:
        """Initialize the inspect form."""
        super().__init__()
        self._sync_titles: List[str] = []
        self._pinned: bool = False
        self._history: List[int] = []
        self._hist_idx: int = -1

        self._widget: Optional[QtWidgets.QWidget] = None
        self._header: Optional[QtWidgets.QLabel] = None
        self.inspector: Optional[QtWidgets.QPlainTextEdit] = None
        self._last_func_start: Optional[int] = None

    def OnCreate(self, form: object) -> None:
        """
        Initialize the UI components.

        Args:
            form: The IDA form handle.
        """
        self._widget = self.FormToPyQtWidget(form)
        layout = QtWidgets.QVBoxLayout(self._widget)

        self._header = QtWidgets.QLabel("Not synced")
        font = self._header.font()
        font.setBold(True)
        self._header.setFont(font)
        layout.addWidget(self._header)

        self.inspector = QtWidgets.QPlainTextEdit()
        self.inspector.setReadOnly(True)
        self.inspector.setPlainText(
            "Use context menu in IDA View / Pseudocode to sync.\n"
        )
        layout.addWidget(self.inspector, 1)

        self.inspector.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.inspector.customContextMenuRequested.connect(self._open_menu)

        self._update_header()

    def OnClose(self, form: object) -> None:
        """
        Clean up when form closes.

        Args:
            form: The IDA form handle.
        """
        self._sync_titles = []
        self._history = []
        self._hist_idx = -1
        self._header = None
        self.inspector = None
        self._widget = None
        # Notify callback to clear global reference
        if SpotlightInspectForm.on_close_callback is not None:
            SpotlightInspectForm.on_close_callback()

    def _update_header(self) -> None:
        """Update the header label text."""
        if self._header is None:
            return
        if not self._sync_titles:
            status = "Not synced"
        else:
            status = "Synced: " + ", ".join(self._sync_titles)
        if self._pinned:
            status += " (Pinned)"
        self._header.setText(status)

    def sync_with_titles(self, titles: List[str]) -> None:
        """
        Sync the inspector with the specified view titles.

        Args:
            titles: List of view titles to sync with.
        """
        titles = [t for t in titles if t]

        # Verify at least one valid code widget exists
        found_valid = False
        for title in titles:
            if find_code_widget_by_title(title) is not None:
                found_valid = True
                break

        if not found_valid:
            ida_kernwin.warning("No matching code widgets found to sync.")
            return

        self._sync_titles = titles
        self._update_header()

        ea = ida_kernwin.get_screen_ea()
        self.update_for_ea(int(ea), push_history=True)

    def unsync(self) -> None:
        """Remove sync association."""
        self._sync_titles = []
        self._update_header()

    def toggle_pin(self) -> None:
        """Toggle the pinned state."""
        self._pinned = not self._pinned
        self._update_header()

    def history_back(self) -> None:
        """Navigate back in history."""
        if self._hist_idx > 0:
            self._hist_idx -= 1
            ea = self._history[self._hist_idx]
            self.update_for_ea(ea, push_history=False)

    def history_forward(self) -> None:
        """Navigate forward in history."""
        if self._hist_idx + 1 < len(self._history):
            self._hist_idx += 1
            ea = self._history[self._hist_idx]
            self.update_for_ea(ea, push_history=False)

    def _open_menu(self, pos: QtCore.QPoint) -> None:
        """
        Show the context menu.

        Args:
            pos: The position where the menu was requested.
        """
        menu = QtWidgets.QMenu(self.inspector)

        act_unsync = QtGui.QAction("Unsync", self.inspector)
        act_unsync.triggered.connect(self.unsync)
        menu.addAction(act_unsync)

        menu.addSeparator()

        act_pin = QtGui.QAction("Pin / Unpin", self.inspector)
        act_pin.triggered.connect(self.toggle_pin)
        menu.addAction(act_pin)

        menu.addSeparator()

        act_back = QtGui.QAction("Back", self.inspector)
        act_back.triggered.connect(self.history_back)
        menu.addAction(act_back)

        act_fwd = QtGui.QAction("Forward", self.inspector)
        act_fwd.triggered.connect(self.history_forward)
        menu.addAction(act_fwd)

        menu.exec_(self.inspector.mapToGlobal(pos))

    def on_screen_ea_changed(self, title: str, ea: int) -> None:
        """
        Handle screen EA change events.

        Called by UI hooks when the cursor moves in a synced view.

        Args:
            title: The view title where the change occurred.
            ea: The new cursor address.
        """
        if self._pinned:
            return
        if title not in self._sync_titles:
            return
        self.update_for_ea(ea, push_history=True)

    def _push_history(self, start_ea: int) -> None:
        """
        Add an address to the navigation history.

        Args:
            start_ea: The function start address to add.
        """
        if (
            self._hist_idx >= 0
            and self._history
            and self._history[self._hist_idx] == start_ea
        ):
            return
        if self._hist_idx < len(self._history) - 1:
            self._history = self._history[: self._hist_idx + 1]
        self._history.append(start_ea)
        self._hist_idx = len(self._history) - 1

    def update_for_ea(self, ea: int, push_history: bool) -> None:
        """
        Update the inspector for a given address.

        Args:
            ea: The address to inspect.
            push_history: Whether to add to navigation history.
        """
        if not qt_alive(self.inspector):
            return

        start = func_start_from_any_ea(ea)
        if start is None:
            self.inspector.setPlainText("No function at cursor.")
            return

        if self._last_func_start == start and push_history:
            return
        self._last_func_start = start

        result = CTX.results.get(start)
        if not result:
            self.inspector.setPlainText(
                f"Function {fmt_ea(start)} not scored.\nRun Scan in IDA Spotlight View."
            )
            return

        rows_all = sorted(
            list(CTX.results.values()),
            key=lambda r: (-float(r.get("final_score", 0.0)), int(r.get("length", 0))),
        )
        tiers = compute_priority_tiers(rows_all)
        priority = tiers.get(start, "low")

        text = render_inspector(result, priority_name=priority)
        self.inspector.setPlainText(text)

        if push_history:
            self._push_history(start)


# ----------------------------------------------------------------------
# View Form
# ----------------------------------------------------------------------

# Table column indices
_COL_FUNCTION: int = 0
_COL_START: int = 1
_COL_LENGTH: int = 2
_COL_SCORE: int = 3
_COL_REASON: int = 4
_COL_CATEGORIES: int = 5
_NUM_COLUMNS: int = 6


class SpotlightViewForm(ida_kernwin.PluginForm):
    """
    Main IDA Spotlight results view.

    Shows a sortable table of scored functions with filtering,
    export capabilities, and an integrated inspector panel.

    Attributes:
        inspect_callback: Optional callback to open inspector for a given EA.
    """

    # Callback to open inspector for a given EA (set externally to avoid circular imports)
    inspect_callback: Optional[Callable[[int], None]] = None

    def __init__(self) -> None:
        """Initialize the view form."""
        super().__init__()
        self._rows: List[Dict[str, Any]] = []
        self._tiers: Dict[int, str] = {}
        self._hide_low_priority: bool = True
        self._hide_library: bool = True
        self._scanner: Optional[ChunkedScanner] = None

        # UI components (initialized in OnCreate)
        self._widget: Optional[QtWidgets.QWidget] = None
        self._btn_scan: Optional[QtWidgets.QPushButton] = None
        self._btn_export: Optional[QtWidgets.QPushButton] = None
        self._progress: Optional[QtWidgets.QProgressBar] = None
        self._lbl_status: Optional[QtWidgets.QLabel] = None
        self._table: Optional[SpotlightTableWidget] = None
        self._search_edit: Optional[QtWidgets.QLineEdit] = None
        self._inspector: Optional[QtWidgets.QPlainTextEdit] = None

    def OnCreate(self, form: object) -> None:
        """
        Initialize the UI components.

        Args:
            form: The IDA form handle.
        """
        self._widget = self.FormToPyQtWidget(form)
        root_layout = QtWidgets.QVBoxLayout(self._widget)

        # Top toolbar
        toolbar = QtWidgets.QHBoxLayout()

        self._btn_scan = QtWidgets.QPushButton("Scan")
        self._btn_scan.clicked.connect(self.start_scan)
        toolbar.addWidget(self._btn_scan)

        self._btn_export = QtWidgets.QPushButton("Export…")
        self._btn_export.clicked.connect(self._export_dialog)
        toolbar.addWidget(self._btn_export)

        self._progress = QtWidgets.QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        toolbar.addWidget(self._progress, 1)

        self._lbl_status = QtWidgets.QLabel("Ready")
        toolbar.addWidget(self._lbl_status)

        root_layout.addLayout(toolbar)

        # Main splitter (table + inspector)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        root_layout.addWidget(splitter, 1)

        # Left panel (table + search)
        left_panel = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self._table = SpotlightTableWidget(0, _NUM_COLUMNS)
        self._table.setHorizontalHeaderLabels([
            "Function", "Start", "Length", "Score", "Top reason", "Categories"
        ])
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self._table.setSortingEnabled(False)
        self._table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._table_menu)
        self._table.itemSelectionChanged.connect(self._on_row_selected)
        self._table.doubleClicked.connect(self._on_double_click)
        self._table.enter_pressed.connect(self._jump_selected)
        left_layout.addWidget(self._table, 1)

        # Configure column widths
        self._table.setColumnWidth(_COL_FUNCTION, 240)
        self._table.setColumnWidth(_COL_START, 90)
        self._table.setColumnWidth(_COL_LENGTH, 90)
        self._table.setColumnWidth(_COL_SCORE, 80)
        self._table.setColumnWidth(_COL_REASON, 260)
        self._table.setColumnWidth(_COL_CATEGORIES, 220)
        self._table.horizontalHeader().setStretchLastSection(True)

        # Search bar
        search_layout = QtWidgets.QHBoxLayout()
        search_layout.addWidget(QtWidgets.QLabel("Search:"))
        self._search_edit = QtWidgets.QLineEdit()
        self._search_edit.setPlaceholderText("Filter by function name (substring)…")
        self._search_edit.textChanged.connect(self._populate)
        search_layout.addWidget(self._search_edit, 1)
        left_layout.addLayout(search_layout)

        splitter.addWidget(left_panel)

        # Right panel (inspector)
        right_panel = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)

        title_label = QtWidgets.QLabel("Quick Inspector")
        font = title_label.font()
        font.setBold(True)
        title_label.setFont(font)
        right_layout.addWidget(title_label)

        self._inspector = QtWidgets.QPlainTextEdit()
        self._inspector.setReadOnly(True)
        self._inspector.setPlainText("Select a function to see details.")
        right_layout.addWidget(self._inspector, 1)

        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

    def start_scan(self) -> None:
        """Start scanning all functions."""
        if not CTX.signals:
            ida_kernwin.warning("IDA Spotlight: spotlight.json not loaded.")
            return

        self._btn_scan.setEnabled(False)
        self._progress.setValue(0)
        self._lbl_status.setText("Scanning…")
        self._inspector.setPlainText("Scanning…")

        self._scanner = ChunkedScanner(chunk_size=100)
        self._scanner.progress.connect(self._progress.setValue)
        self._scanner.finished.connect(self._scan_done)
        self._scanner.start()

    def _scan_done(self, err: str) -> None:
        """
        Handle scan completion.

        Args:
            err: Error message, empty on success.
        """
        self._btn_scan.setEnabled(True)
        if err:
            self._lbl_status.setText("Error")
            self._inspector.setPlainText(f"Scan failed:\n{err}")
            return
        self._lbl_status.setText(f"Done in {CTX.last_scan_seconds:.1f}s")
        self._populate()
        log_kb_sample_correlation()

    def _get_rows(self) -> List[Dict[str, Any]]:
        """
        Get filtered and sorted rows for display.

        Returns:
            A list of function result dictionaries.
        """
        rows = list(CTX.results.values())
        rows.sort(
            key=lambda r: (-float(r.get("final_score", 0.0)), int(r.get("length", 0)))
        )

        if self._hide_low_priority:
            rows = [r for r in rows if float(r.get("final_score", 0.0)) > 0.0]

        if self._hide_library:
            rows = [r for r in rows if not r.get("is_library", False)]

        query = (self._search_edit.text() or "").strip().lower()
        if query:
            rows = [r for r in rows if query in r.get("name", "").lower()]

        return rows

    def _populate(self) -> None:
        """Populate the table with current results."""
        rows = self._get_rows()
        tiers = compute_priority_tiers(rows)

        self._rows = rows
        self._tiers = tiers

        self._table.setRowCount(len(rows))

        for index, result in enumerate(rows):
            ea = int(result["ea"])
            length = int(result.get("length", 0))
            score = float(result.get("final_score", 0.0))

            # Determine row color
            if result.get("is_library", False):
                color = QtGui.QColor(160, 220, 255)
            else:
                priority = tiers.get(ea, "low")
                color = priority_color(priority)

            # Create table items
            item_func = QtWidgets.QTableWidgetItem(result.get("name", ""))
            item_func.setToolTip(result.get("name", ""))
            item_start = QtWidgets.QTableWidgetItem(fmt_ea(ea))
            item_len = QtWidgets.QTableWidgetItem(hex(length))
            item_score = QtWidgets.QTableWidgetItem(f"{score:.2f}")
            item_reason = QtWidgets.QTableWidgetItem(top_reason_str(result))
            item_cats = QtWidgets.QTableWidgetItem(categories_str(result))

            items = [item_func, item_start, item_len, item_score, item_reason, item_cats]
            for col, item in enumerate(items):
                item.setData(QtCore.Qt.UserRole, ea)
                if color is not None:
                    item.setBackground(QtGui.QBrush(color))
                self._table.setItem(index, col, item)

        if not rows:
            self._inspector.setPlainText("No results.")
        else:
            self._inspector.setPlainText("Select a function to see details.")

    def _selected_start_ea(self) -> Optional[int]:
        """
        Get the EA of the currently selected row.

        Returns:
            The function start EA, or None if no selection.
        """
        row = self._table.currentRow()
        if row < 0:
            return None
        item = self._table.item(row, 0)
        if not item:
            return None
        ea = item.data(QtCore.Qt.UserRole)
        try:
            return int(ea)
        except Exception:
            return None

    def _on_row_selected(self) -> None:
        """Update inspector when row selection changes."""
        start_ea = self._selected_start_ea()
        if start_ea is None:
            return
        result = CTX.results.get(start_ea)
        if not result:
            return
        priority = self._tiers.get(start_ea, "low")
        self._inspector.setPlainText(render_inspector(result, priority_name=priority))

    def _jump_selected(self) -> None:
        """Jump to the selected function in IDA."""
        start_ea = self._selected_start_ea()
        if start_ea is None:
            return
        ida_kernwin.jumpto(start_ea)

    def _inspect_here(self) -> None:
        """Open the standalone inspector for the selected function."""
        start_ea = self._selected_start_ea()
        if start_ea is None:
            return
        if SpotlightViewForm.inspect_callback is not None:
            SpotlightViewForm.inspect_callback(start_ea)

    def _on_double_click(self, index: QtCore.QModelIndex) -> None:
        """
        Handle double-click on a row.

        Args:
            index: The clicked model index.
        """
        self._jump_selected()

    def _current_cell_text(self) -> str:
        """
        Get text from the current cell.

        Returns:
            The cell text, or empty string.
        """
        row = self._table.currentRow()
        col = self._table.currentColumn()
        item = self._table.item(row, col) if (row >= 0 and col >= 0) else None
        return item.text() if item else ""

    def _current_row_text(self, row: int) -> str:
        """
        Get tab-separated text from a row.

        Args:
            row: The row index.

        Returns:
            Tab-separated cell values.
        """
        cells = []
        for col in range(self._table.columnCount()):
            item = self._table.item(row, col)
            cells.append(item.text() if item else "")
        return "\t".join(cells)

    def _selected_rows_text(self) -> str:
        """
        Get newline-separated text from selected rows.

        Returns:
            Newline-separated row values.
        """
        rows = sorted({idx.row() for idx in self._table.selectionModel().selectedRows()})
        return "\n".join(self._current_row_text(r) for r in rows)

    def _table_menu(self, pos: QtCore.QPoint) -> None:
        """
        Show the table context menu.

        Args:
            pos: The position where the menu was requested.
        """
        menu = QtWidgets.QMenu()

        # Filter toggles
        act_hide_low = menu.addAction("Hide Low Priority")
        act_hide_low.setCheckable(True)
        act_hide_low.setChecked(self._hide_low_priority)

        act_hide_lib = menu.addAction("Hide Library Functions")
        act_hide_lib.setCheckable(True)
        act_hide_lib.setChecked(self._hide_library)

        act_inspect_here = menu.addAction("Inspect here")

        menu.addSeparator()

        # Copy submenu
        copy_menu = menu.addMenu("Copy")
        act_copy_cell = copy_menu.addAction("Copy cell")
        act_copy_row = copy_menu.addAction("Copy row")
        act_copy_rows = copy_menu.addAction("Copy selected rows")

        menu.addSeparator()

        act_jump = menu.addAction("Jump to function")

        menu.addSeparator()

        # Export submenu
        export_menu = menu.addMenu("Export")
        act_export_csv = export_menu.addAction("Export CSV…")
        act_export_json = export_menu.addAction("Export JSON…")

        action = menu.exec_(self._table.mapToGlobal(pos))
        if not action:
            return

        # Handle menu actions
        if action == act_hide_low:
            self._hide_low_priority = not self._hide_low_priority
            self._populate()
        elif action == act_hide_lib:
            self._hide_library = not self._hide_library
            self._populate()
        elif action == act_inspect_here:
            self._inspect_here()
        elif action == act_copy_cell:
            QtWidgets.QApplication.clipboard().setText(self._current_cell_text())
        elif action == act_copy_row:
            row = self._table.currentRow()
            if row >= 0:
                QtWidgets.QApplication.clipboard().setText(self._current_row_text(row))
        elif action == act_copy_rows:
            text = self._selected_rows_text()
            if text:
                QtWidgets.QApplication.clipboard().setText(text)
        elif action == act_jump:
            self._jump_selected()
        elif action == act_export_csv:
            self._export_csv()
        elif action == act_export_json:
            self._export_json()

    def _export_dialog(self) -> None:
        """Show the export format selection dialog."""
        menu = QtWidgets.QMenu()
        act_csv = menu.addAction("Export CSV…")
        act_json = menu.addAction("Export JSON…")
        action = menu.exec_(QtGui.QCursor.pos())
        if action == act_csv:
            self._export_csv()
        elif action == act_json:
            self._export_json()

    def _export_csv(self) -> None:
        """Export results to CSV file."""
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self._widget, "Export CSV", "", "CSV (*.csv)"
        )
        if not file_path:
            return

        rows = self._rows if self._rows else self._get_rows()
        tiers = compute_priority_tiers(rows)

        with open(file_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow([
                "Function", "Start", "Length", "Score",
                "Priority", "Library", "Top reason", "Categories"
            ])
            for result in rows:
                ea = int(result["ea"])
                writer.writerow([
                    result.get("name", ""),
                    fmt_ea(ea),
                    hex(int(result.get("length", 0))),
                    f"{float(result.get('final_score', 0.0)):.2f}",
                    tiers.get(ea, "low"),
                    "yes" if result.get("is_library") else "no",
                    top_reason_str(result),
                    categories_str(result),
                ])

    def _export_json(self) -> None:
        """Export results to JSON file."""
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self._widget, "Export JSON", "", "JSON (*.json)"
        )
        if not file_path:
            return

        rows = self._rows if self._rows else self._get_rows()
        tiers = compute_priority_tiers(rows)

        output: List[Dict[str, Any]] = []
        for result in rows:
            ea = int(result["ea"])
            output.append({
                "name": result.get("name", ""),
                "start_ea": ea,
                "start_ea_hex": fmt_ea(ea),
                "length": int(result.get("length", 0)),
                "length_hex": hex(int(result.get("length", 0))),
                "is_library": bool(result.get("is_library", False)),
                "base_score": float(result.get("base_score", 0.0)),
                "context_bonus": float(result.get("context_bonus", 0.0)),
                "final_score": float(result.get("final_score", 0.0)),
                "priority": tiers.get(ea, "low"),
                "top_reason": top_reason_str(result),
                "categories": [
                    key for key, value in result.get("category_hits", {}).items() if value
                ],
                "reasons": list(result.get("reasons", [])),
            })

        with open(file_path, "w", encoding="utf-8") as json_file:
            json.dump(output, json_file, indent=2)
