from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import QModelIndex, QTimer, Qt
from PySide6.QtGui import QFontDatabase, QKeySequence, QTextCursor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from models import to_json_compatible


def display_value(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        if not value:
            return "-"
        if all(not isinstance(item, (list, dict)) for item in value):
            return ", ".join(str(item) for item in value)
        return json.dumps(to_json_compatible(value), ensure_ascii=False)
    if isinstance(value, dict):
        if not value:
            return "-"
        return json.dumps(to_json_compatible(value), ensure_ascii=False)
    return str(value)


class SelectAllTextDelegate(QStyledItemDelegate):
    """Show a read-only text editor and select the entire cell on double-click."""

    def createEditor(
        self,
        parent: QWidget,
        option: QStyleOptionViewItem,
        index: QModelIndex,
    ) -> QWidget:
        del option, index
        editor = QLineEdit(parent)
        editor.setReadOnly(True)
        editor.setFrame(False)
        return editor

    def setEditorData(self, editor: QWidget, index: QModelIndex) -> None:
        if isinstance(editor, QLineEdit):
            editor.setText(str(index.data(Qt.ItemDataRole.DisplayRole) or ""))
            QTimer.singleShot(0, editor.selectAll)

    def setModelData(self, editor: QWidget, model, index: QModelIndex) -> None:  # type: ignore[no-untyped-def]
        del editor, model, index

    def updateEditorGeometry(
        self,
        editor: QWidget,
        option: QStyleOptionViewItem,
        index: QModelIndex,
    ) -> None:
        del index
        editor.setGeometry(option.rect)


class CopyableTable(QTableWidget):
    def __init__(self, columns: list[str], parent: QWidget | None = None) -> None:
        super().__init__(0, len(columns), parent)
        self.setHorizontalHeaderLabels(columns)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked)
        self.setItemDelegate(SelectAllTextDelegate(self))
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.horizontalHeader().setStretchLastSection(True)

    def keyPressEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.matches(QKeySequence.StandardKey.Copy):
            if self.copy_selection():
                return
        super().keyPressEvent(event)

    def contextMenuEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        menu = QMenu(self)
        action = menu.addAction("Copy")
        action.setEnabled(bool(self.selectedIndexes()))
        action.triggered.connect(self.copy_selection)
        menu.exec(event.globalPos())

    def copy_selection(self) -> bool:
        indexes = sorted(self.selectedIndexes(), key=lambda item: (item.row(), item.column()))
        if not indexes:
            return False
        rows: dict[int, list[str]] = {}
        for index in indexes:
            rows.setdefault(index.row(), []).append(str(index.data() or ""))
        QApplication.clipboard().setText(
            "\n".join("\t".join(values) for values in rows.values())
        )
        return True


class CopyableTree(QTreeWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked)
        self.setItemDelegate(SelectAllTextDelegate(self))

    def keyPressEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.matches(QKeySequence.StandardKey.Copy):
            if self.copy_selection():
                return
        super().keyPressEvent(event)

    def contextMenuEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        menu = QMenu(self)
        action = menu.addAction("Copy")
        action.setEnabled(bool(self.selectedIndexes()))
        action.triggered.connect(self.copy_selection)
        menu.exec(event.globalPos())

    def copy_selection(self) -> bool:
        indexes = self.selectedIndexes()
        if not indexes:
            return False
        QApplication.clipboard().setText("\n".join(str(index.data() or "") for index in indexes))
        return True


class ObjectTree(CopyableTree):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setHeaderLabels(["Key", "Value"])
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.header().setStretchLastSection(True)

    def set_data(self, data: Any) -> None:
        self.clear()
        self._append_value(None, "root", data)
        self.expandToDepth(1)

    def _append_value(
        self, parent: QTreeWidgetItem | None, key: str, value: Any
    ) -> None:
        if isinstance(value, dict):
            item = QTreeWidgetItem([str(key), f"{len(value)} key(s)"])
            self._add_item(parent, item)
            for child_key, child_value in value.items():
                self._append_value(item, str(child_key), child_value)
        elif isinstance(value, (list, tuple)):
            item = QTreeWidgetItem([str(key), f"{len(value)} item(s)"])
            self._add_item(parent, item)
            for index, child_value in enumerate(value):
                self._append_value(item, f"[{index}]", child_value)
        elif isinstance(value, bytes):
            self._add_item(parent, QTreeWidgetItem([str(key), f"<{len(value)} bytes>"]))
        else:
            self._add_item(parent, QTreeWidgetItem([str(key), display_value(value)]))

    def _add_item(self, parent: QTreeWidgetItem | None, item: QTreeWidgetItem) -> None:
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEditable)
        if parent is None:
            self.addTopLevelItem(item)
        else:
            parent.addChild(item)


class SearchableText(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search")
        self.next_button = QPushButton("Next")
        self.next_button.setFixedWidth(64)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.text.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))

        controls = QHBoxLayout()
        controls.setContentsMargins(0, 0, 0, 0)
        controls.addWidget(self.search)
        controls.addWidget(self.next_button)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(controls)
        layout.addWidget(self.text)

        self.search.returnPressed.connect(self.find_next)
        self.next_button.clicked.connect(self.find_next)

    def set_text(self, value: str) -> None:
        self.text.setPlainText(value)
        self.text.moveCursor(QTextCursor.MoveOperation.Start)

    def set_json(self, value: Any) -> None:
        self.set_text(json.dumps(to_json_compatible(value), ensure_ascii=False, indent=2))

    def find_next(self) -> None:
        term = self.search.text()
        if not term:
            return
        if not self.text.find(term):
            cursor = self.text.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            self.text.setTextCursor(cursor)
            self.text.find(term)
