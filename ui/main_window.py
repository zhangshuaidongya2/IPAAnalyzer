from __future__ import annotations

import json
import plistlib
import zipfile
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, Slot
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QSplitter,
    QStackedWidget,
    QStyle,
    QTabWidget,
    QTableWidgetItem,
    QToolBar,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from analyzer import IPAAnalysisError, IPAAnalyzer
from analyzer.utils import format_bytes
from models import IPAAnalysisResult, to_json_compatible

from .widgets.data_views import CopyableTable, CopyableTree, ObjectTree, SearchableText


def _display(value: Any) -> str:
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


def _fill_key_value_table(table: CopyableTable, rows: list[tuple[str, Any]]) -> None:
    table.setRowCount(len(rows))
    for row, (label, value) in enumerate(rows):
        table.setItem(row, 0, QTableWidgetItem(label))
        table.setItem(row, 1, QTableWidgetItem(_display(value)))
    table.resizeRowsToContents()


class AnalysisWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = path

    @Slot()
    def run(self) -> None:
        try:
            self.completed.emit(IPAAnalyzer().analyze(self.path))
        except IPAAnalysisError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"Unexpected analysis failure: {exc}")


class OverviewPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.summary = CopyableTable(["Field", "Value"])
        self.info = ObjectTree()
        self.warnings = SearchableText()
        tabs = QTabWidget()
        tabs.addTab(self.summary, "Summary")
        tabs.addTab(self.info, "Info.plist")
        tabs.addTab(self.warnings, "Warnings")
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)

    def set_result(self, result: IPAAnalysisResult) -> None:
        basic, macho, signing, sizes = result.basic, result.macho, result.signing, result.size_info
        devices = {1: "iPhone/iPod", 2: "iPad", 3: "Apple TV", 4: "Apple Watch"}
        device_family = [devices.get(value, str(value)) for value in basic.get("device_family") or []]
        _fill_key_value_table(
            self.summary,
            [
                ("App Name", basic.get("display_name") or basic.get("name")),
                ("Bundle ID", basic.get("bundle_id")),
                ("Version", basic.get("version")),
                ("Build", basic.get("build")),
                ("Minimum OS", basic.get("minimum_os") or macho.get("minimum_os")),
                ("Executable", basic.get("executable")),
                ("Architecture", macho.get("architectures")),
                ("SDK", macho.get("sdk") or basic.get("sdk_name")),
                ("Supported Devices", device_family),
                ("IPA Size", format_bytes(sizes.get("ipa_size"))),
                ("Executable Size", format_bytes(sizes.get("main_executable_size"))),
                ("Signature Type", signing.get("type")),
                ("FairPlay Encrypted", macho.get("encrypted", False)),
                ("Main App", basic.get("main_app_path")),
            ],
        )
        self.info.set_data(result.raw.get("info_plist", {}))
        self.warnings.set_text("\n".join(result.errors) if result.errors else "No warnings.")


class SigningPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.summary = CopyableTable(["Field", "Value"])
        self.profile = ObjectTree()
        self.certificates = CopyableTable(
            ["Subject", "Issuer", "Serial", "Not Before", "Not After", "SHA256"]
        )
        self.raw = SearchableText()
        tabs = QTabWidget()
        tabs.addTab(self.summary, "Signature")
        tabs.addTab(self.profile, "Provisioning Profile")
        tabs.addTab(self.certificates, "Certificates")
        tabs.addTab(self.raw, "Raw")
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)

    def set_result(self, result: IPAAnalysisResult) -> None:
        signing = result.signing
        _fill_key_value_table(
            self.summary,
            [
                ("Type", signing.get("type")),
                ("Team ID", signing.get("team_id")),
                ("Profile", signing.get("profile_name")),
                ("Profile UUID", signing.get("profile_uuid")),
                ("Created", signing.get("creation_date")),
                ("Expires", signing.get("expiration_date")),
                ("Evidence", signing.get("evidence")),
                ("Identifier", signing.get("code_signature", {}).get("Identifier")),
                ("Authorities", signing.get("code_signature", {}).get("Authority")),
            ],
        )
        self.profile.set_data(result.provision)
        self.certificates.setRowCount(len(result.certificates))
        keys = ("subject", "issuer", "serial_number", "not_before", "not_after", "sha256_fingerprint")
        for row, certificate in enumerate(result.certificates):
            for column, key in enumerate(keys):
                self.certificates.setItem(row, column, QTableWidgetItem(_display(certificate.get(key))))
        self.raw.set_json(
            {
                "mobileprovision": result.raw.get("mobileprovision"),
                "mobileprovision_command": result.raw.get("mobileprovision_command"),
                "codesign": result.raw.get("codesign"),
                "certificate_commands": result.raw.get("certificate_commands"),
            }
        )


class EntitlementsPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.effective = ObjectTree()
        self.profile = ObjectTree()
        self.codesign = ObjectTree()
        self.raw = SearchableText()
        tabs = QTabWidget()
        tabs.addTab(self.effective, "Effective")
        tabs.addTab(self.codesign, "Code Signature")
        tabs.addTab(self.profile, "Profile")
        tabs.addTab(self.raw, "Raw")
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)

    def set_result(self, result: IPAAnalysisResult) -> None:
        self.effective.set_data(result.entitlements.get("effective", {}))
        self.codesign.set_data(result.entitlements.get("codesign", {}))
        self.profile.set_data(result.entitlements.get("profile", {}))
        self.raw.set_json(result.raw.get("entitlements", {}))


class PermissionsPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.table = CopyableTable(["Permission", "Key", "Declared", "Description"])
        layout = QVBoxLayout(self)
        layout.addWidget(self.table)

    def set_result(self, result: IPAAnalysisResult) -> None:
        self.table.setRowCount(len(result.permissions))
        for row, permission in enumerate(result.permissions):
            values = (
                permission.get("permission"),
                permission.get("key"),
                "Yes" if permission.get("declared") else "No",
                permission.get("description") or "-",
            )
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(str(value)))


class MachOPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.summary = CopyableTable(["Field", "Value"])
        self.libraries = CopyableTable(["Dynamic Library"])
        self.commands = CopyableTable(["Load Command"])
        self.raw = SearchableText()
        tabs = QTabWidget()
        tabs.addTab(self.summary, "Summary")
        tabs.addTab(self.libraries, "Libraries")
        tabs.addTab(self.commands, "Load Commands")
        tabs.addTab(self.raw, "Raw")
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)

    def set_result(self, result: IPAAnalysisResult) -> None:
        macho = result.macho
        _fill_key_value_table(
            self.summary,
            [
                ("File Type", macho.get("file_type")),
                ("Architectures", macho.get("architectures")),
                ("Minimum OS", macho.get("minimum_os")),
                ("SDK", macho.get("sdk")),
                ("PIE", macho.get("pie")),
                ("Encrypted", macho.get("encrypted")),
                ("Crypt ID", macho.get("cryptid")),
                ("Encryption Info", macho.get("encryption_info")),
                ("UUID", macho.get("uuids")),
                ("RPATH", macho.get("rpaths")),
                ("SHA256", result.hashes.get("executable_sha256")),
            ],
        )
        self._fill_one_column(self.libraries, macho.get("libraries", []))
        self._fill_one_column(self.commands, macho.get("load_commands", []))
        self.raw.set_json(result.raw.get("macho", {}))

    @staticmethod
    def _fill_one_column(table: CopyableTable, values: list[Any]) -> None:
        table.setRowCount(len(values))
        for row, value in enumerate(values):
            table.setItem(row, 0, QTableWidgetItem(str(value)))


class URLSchemesPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.table = CopyableTable(["Category", "Value"])
        layout = QVBoxLayout(self)
        layout.addWidget(self.table)

    def set_result(self, result: IPAAnalysisResult) -> None:
        rows: list[tuple[str, str]] = []
        labels = {
            "registered": "Registered URL Scheme",
            "query_schemes": "Query Scheme",
            "associated_domains": "Associated Domain",
        }
        for key, label in labels.items():
            rows.extend((label, value) for value in result.url_schemes.get(key, []))
        self.table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(value))


class FrameworksPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.items: list[dict[str, Any]] = []
        self.table = CopyableTable(
            ["Name", "Version", "Architecture", "Size", "Signed", "SHA256"]
        )
        self.details = SearchableText()
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.details)
        splitter.setSizes([420, 260])
        layout = QVBoxLayout(self)
        layout.addWidget(splitter)
        self.table.itemSelectionChanged.connect(self._show_selection)

    def set_result(self, result: IPAAnalysisResult) -> None:
        self.items = result.frameworks
        self.table.setRowCount(len(self.items))
        for row, framework in enumerate(self.items):
            values = (
                framework.get("name"),
                framework.get("version"),
                ", ".join(framework.get("architectures", [])),
                format_bytes(framework.get("size")),
                "Yes" if framework.get("signed") else "No",
                framework.get("sha256"),
            )
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(_display(value)))
        self.details.set_text("")

    def _show_selection(self) -> None:
        row = self.table.currentRow()
        if 0 <= row < len(self.items):
            self.details.set_json(self.items[row])


class ExtensionsPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.extension_items: list[dict[str, Any]] = []
        self.bundle_items: list[dict[str, Any]] = []
        self.extensions = CopyableTable(["Name", "Bundle ID", "Type", "Version", "Executable"])
        self.bundles = CopyableTable(["Name", "Bundle ID", "Type", "Version", "Executable"])
        self.details = SearchableText()
        tabs = QTabWidget()
        tabs.addTab(self.extensions, "Extensions")
        tabs.addTab(self.bundles, "Watch / App Clips")
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(tabs)
        splitter.addWidget(self.details)
        splitter.setSizes([420, 260])
        layout = QVBoxLayout(self)
        layout.addWidget(splitter)
        self.extensions.itemSelectionChanged.connect(
            lambda: self._show_selection(self.extensions, self.extension_items)
        )
        self.bundles.itemSelectionChanged.connect(
            lambda: self._show_selection(self.bundles, self.bundle_items)
        )

    def set_result(self, result: IPAAnalysisResult) -> None:
        self.extension_items = result.extensions
        self.bundle_items = result.embedded_bundles
        self._fill(self.extensions, self.extension_items)
        self._fill(self.bundles, self.bundle_items)
        self.details.set_text("")

    @staticmethod
    def _fill(table: CopyableTable, items: list[dict[str, Any]]) -> None:
        table.setRowCount(len(items))
        for row, item in enumerate(items):
            values = (
                item.get("name"),
                item.get("bundle_id"),
                item.get("type"),
                item.get("version"),
                item.get("executable"),
            )
            for column, value in enumerate(values):
                table.setItem(row, column, QTableWidgetItem(_display(value)))

    def _show_selection(self, table: CopyableTable, items: list[dict[str, Any]]) -> None:
        row = table.currentRow()
        if 0 <= row < len(items):
            self.details.set_json(items[row])


class FilesPage(QWidget):
    PREVIEW_LIMIT = 2 * 1024 * 1024

    def __init__(self) -> None:
        super().__init__()
        self.ipa_path = ""
        self.metadata: dict[str, dict[str, Any]] = {}
        self.tree = CopyableTree()
        self.tree.setHeaderLabels(["IPA Contents", "Size"])
        self.tree.setUniformRowHeights(True)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.details = SearchableText()
        splitter = QSplitter()
        splitter.addWidget(self.tree)
        splitter.addWidget(self.details)
        splitter.setSizes([360, 700])
        layout = QVBoxLayout(self)
        layout.addWidget(splitter)
        self.tree.currentItemChanged.connect(self._show_item)

    def set_result(self, result: IPAAnalysisResult) -> None:
        self.ipa_path = result.ipa_path
        self.metadata = {str(item["relative_path"]): item for item in result.files}
        self.tree.clear()
        nodes: dict[str, QTreeWidgetItem] = {}
        for entry in result.files:
            relative = str(entry["relative_path"])
            parts = relative.split("/")
            for index in range(len(parts)):
                partial = "/".join(parts[: index + 1])
                if partial in nodes:
                    continue
                node = QTreeWidgetItem([parts[index], ""])
                node.setFlags(node.flags() | Qt.ItemFlag.ItemIsEditable)
                node.setData(0, Qt.ItemDataRole.UserRole, partial)
                parent_path = "/".join(parts[:index])
                if parent_path and parent_path in nodes:
                    nodes[parent_path].addChild(node)
                else:
                    self.tree.addTopLevelItem(node)
                nodes[partial] = node
            node = nodes[relative]
            if not entry.get("is_directory"):
                node.setText(1, format_bytes(int(entry.get("size", 0))))
        self.tree.expandToDepth(1)
        self.details.set_text("")

    def _show_item(
        self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None
    ) -> None:
        del previous
        if current is None:
            return
        relative = str(current.data(0, Qt.ItemDataRole.UserRole) or "")
        metadata = self.metadata.get(relative, {"relative_path": relative, "is_directory": True})
        text = json.dumps(to_json_compatible(metadata), ensure_ascii=False, indent=2)
        if metadata.get("is_directory"):
            self.details.set_text(text)
            return
        try:
            preview = self._read_preview(relative, int(metadata.get("size", 0)))
        except (OSError, KeyError, zipfile.BadZipFile, ValueError) as exc:
            preview = f"Preview unavailable: {exc}"
        self.details.set_text(f"{text}\n\n{preview}")

    def _read_preview(self, relative: str, size: int) -> str:
        if size > self.PREVIEW_LIMIT:
            return f"Preview omitted for files larger than {format_bytes(self.PREVIEW_LIMIT)}."
        with zipfile.ZipFile(self.ipa_path, "r") as archive:
            member = archive.getinfo(relative)
            if member.file_size > self.PREVIEW_LIMIT:
                raise ValueError("archive entry exceeds the preview limit")
            data = archive.read(member)
        if relative.endswith((".plist", ".entitlements")):
            try:
                value = plistlib.loads(data)
                return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True).decode("utf-8")
            except (plistlib.InvalidFileException, ValueError, TypeError):
                pass
        try:
            decoded = data.decode("utf-8")
            if "\x00" not in decoded:
                return decoded
        except UnicodeDecodeError:
            pass
        visible = data[:65536]
        lines = []
        for offset in range(0, len(visible), 16):
            chunk = visible[offset : offset + 16]
            hexadecimal = " ".join(f"{byte:02x}" for byte in chunk)
            printable = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
            lines.append(f"{offset:08x}  {hexadecimal:<47}  {printable}")
        if len(data) > len(visible):
            lines.append("\nPreview truncated.")
        return "\n".join(lines)


class RawPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.text = SearchableText()
        layout = QVBoxLayout(self)
        layout.addWidget(self.text)

    def set_result(self, result: IPAAnalysisResult) -> None:
        self.text.set_json(result.raw)


class MainWindow(QMainWindow):
    def __init__(self, initial_path: str | None = None) -> None:
        super().__init__()
        self.setWindowTitle("IPA Analyzer")
        self.resize(1180, 760)
        self.setMinimumSize(880, 600)
        self.setAcceptDrops(True)
        self._thread: QThread | None = None
        self._worker: AnalysisWorker | None = None
        self._closing = False
        self._pending_path: str | None = None

        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        self.open_action = QAction(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton),
            "Open IPA",
            self,
        )
        self.open_action.setShortcut("Ctrl+O")
        self.open_action.triggered.connect(self.open_ipa)
        toolbar.addAction(self.open_action)

        self.navigation = QListWidget()
        self.navigation.setFixedWidth(185)
        self.stack = QStackedWidget()
        self.pages: list[tuple[str, QWidget]] = [
            ("Overview", OverviewPage()),
            ("Signing", SigningPage()),
            ("Entitlements", EntitlementsPage()),
            ("Permissions", PermissionsPage()),
            ("Mach-O", MachOPage()),
            ("Frameworks", FrameworksPage()),
            ("Extensions", ExtensionsPage()),
            ("URL Schemes", URLSchemesPage()),
            ("Files", FilesPage()),
            ("Raw Data", RawPage()),
        ]
        for name, page in self.pages:
            self.navigation.addItem(QListWidgetItem(name))
            self.stack.addWidget(page)
        self.navigation.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.navigation.setCurrentRow(0)

        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.navigation)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedWidth(130)
        self.progress.hide()
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().showMessage("No IPA loaded")

        if initial_path:
            QTimer.singleShot(0, lambda: self.load_ipa(initial_path))

    @Slot()
    def open_ipa(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open IPA", "", "IPA files (*.ipa)")
        if path:
            self.load_ipa(path)

    def load_ipa(self, path: str) -> None:
        if self._thread and self._thread.isRunning():
            self._pending_path = path
            self.statusBar().showMessage(f"Queued {Path(path).name}")
            return
        self.open_action.setEnabled(False)
        self.progress.show()
        self.statusBar().showMessage(f"Analyzing {Path(path).name}...")

        thread = QThread(self)
        worker = AnalysisWorker(path)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._analysis_completed)
        worker.failed.connect(self._analysis_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)
        worker.failed.connect(worker.deleteLater)
        thread.finished.connect(self._thread_finished)
        self._thread = thread
        self._worker = worker
        thread.start()

    @Slot(object)
    def _analysis_completed(self, result: IPAAnalysisResult) -> None:
        for _, page in self.pages:
            setter = getattr(page, "set_result", None)
            if setter:
                setter(result)
        app_name = result.basic.get("display_name") or result.basic.get("name") or Path(result.ipa_path).name
        warning_text = f"; {len(result.errors)} warning(s)" if result.errors else ""
        self.setWindowTitle(f"{app_name} - IPA Analyzer")
        self.statusBar().showMessage(f"Analysis complete{warning_text}")
        self.progress.hide()
        self.open_action.setEnabled(True)

    @Slot(str)
    def _analysis_failed(self, message: str) -> None:
        self.statusBar().showMessage("Analysis failed")
        self.progress.hide()
        self.open_action.setEnabled(True)
        QMessageBox.critical(self, "IPA Analyzer", message)

    @Slot()
    def _thread_finished(self) -> None:
        if self._thread:
            self._thread.deleteLater()
        self._thread = None
        self._worker = None
        if self._closing:
            self.close()
        elif self._pending_path:
            path = self._pending_path
            self._pending_path = None
            QTimer.singleShot(0, lambda: self.load_ipa(path))

    def dragEnterEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        if any(url.isLocalFile() and url.toLocalFile().lower().endswith(".ipa") for url in urls):
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if url.isLocalFile() and path.lower().endswith(".ipa"):
                self.load_ipa(path)
                event.acceptProposedAction()
                return

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._thread and self._thread.isRunning():
            self._closing = True
            self.statusBar().showMessage("Waiting for the current analysis to finish...")
            event.ignore()
            return
        event.accept()
