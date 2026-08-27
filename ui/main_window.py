from __future__ import annotations

import json
import plistlib
import sys
import zipfile
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QEvent,
    QObject,
    QSize,
    QStandardPaths,
    QThread,
    QTimer,
    Qt,
    Signal,
    Slot,
)
from PySide6.QtGui import QAction, QCloseEvent, QColor, QIcon, QKeySequence, QPixmap
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTableWidgetItem,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from analyzer import (
    IPAAnalysisError,
    IPAAnalyzer,
    ImageExtractionResult,
    extract_image_resources,
)
from analyzer.utils import format_bytes
from models import IPAAnalysisResult, to_json_compatible

from .widgets.data_views import CopyableTable, CopyableTree, ObjectTree, SearchableText


def _resource_path(relative_path: str) -> Path:
    project_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
    return project_root / relative_path


APP_ICON_PATH = _resource_path("assets/AppIcon-1024.png")


def _mix_color(background: QColor, foreground: QColor, amount: float) -> QColor:
    return QColor(
        round(background.red() + (foreground.red() - background.red()) * amount),
        round(background.green() + (foreground.green() - background.green()) * amount),
        round(background.blue() + (foreground.blue() - background.blue()) * amount),
    )


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


class ImageExportWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, ipa_path: str, destination: str) -> None:
        super().__init__()
        self.ipa_path = ipa_path
        self.destination = destination

    @Slot()
    def run(self) -> None:
        try:
            result = extract_image_resources(self.ipa_path, self.destination)
            self.completed.emit(result)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            self.failed.emit(f"Unable to extract image files: {exc}")
        except Exception as exc:
            self.failed.emit(f"Unexpected image extraction failure: {exc}")


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


class ITunesMetadataPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.summary = CopyableTable(["Field", "Value"])
        self.all_fields = ObjectTree()
        self.xml = SearchableText()
        tabs = QTabWidget()
        tabs.addTab(self.summary, "Summary")
        tabs.addTab(self.all_fields, "All Fields")
        tabs.addTab(self.xml, "XML")
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)

    def set_result(self, result: IPAAnalysisResult) -> None:
        metadata = result.itunes_metadata
        _fill_key_value_table(
            self.summary,
            [
                ("Present", bool(metadata)),
                ("Item Name", metadata.get("itemName")),
                ("Bundle Display Name", metadata.get("bundleDisplayName")),
                ("Bundle ID", metadata.get("softwareVersionBundleId")),
                ("Version", metadata.get("bundleShortVersionString")),
                ("Build", metadata.get("bundleVersion")),
                ("Store Item ID", metadata.get("itemId")),
                ("Artist", metadata.get("artistName")),
                ("Artist ID", metadata.get("artistId")),
                ("Store Account", metadata.get("appleId") or metadata.get("userName")),
                ("Purchase Date", metadata.get("purchaseDate")),
                ("Release Date", metadata.get("releaseDate")),
                ("Genre", metadata.get("genre")),
                ("Genre ID", metadata.get("genreId")),
                ("Kind", metadata.get("kind")),
                ("Rating", metadata.get("rating")),
                ("Copyright", metadata.get("copyright")),
                ("DRM Version", metadata.get("drmVersionNumber")),
                ("Vendor ID", metadata.get("vendorId")),
                ("Game Center", metadata.get("gameCenterEnabled")),
                ("Supported Device IDs", metadata.get("softwareSupportedDeviceIds")),
                ("File Name", metadata.get("fileName")),
            ],
        )
        self.all_fields.set_data(metadata)
        self.xml.set_text(
            result.raw.get("itunes_metadata_xml")
            or "iTunesMetadata.plist is not present in this IPA."
        )


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


class EmptyState(QWidget):
    open_requested = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("emptyState")
        self.setProperty("dragActive", False)
        self._updating_palette = False

        icon = QLabel()
        icon.setObjectName("emptyIcon")
        icon.setFixedSize(96, 96)
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pixmap = QPixmap(str(APP_ICON_PATH))
        if not pixmap.isNull():
            icon.setPixmap(
                pixmap.scaled(
                    QSize(88, 88),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )

        self.title = QLabel("Open an IPA to begin")
        self.title.setObjectName("emptyTitle")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.subtitle = QLabel(
            "Inspect signing, permissions, frameworks, and package contents."
        )
        self.subtitle.setObjectName("emptySubtitle")
        self.subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subtitle.setWordWrap(True)

        self.open_button = QPushButton("Choose IPA File...")
        self.open_button.setObjectName("openIpaButton")
        self.open_button.setDefault(True)
        self.open_button.clicked.connect(self.open_requested)

        self.hint = QLabel("or drag and drop an .ipa file here")
        self.hint.setObjectName("emptyHint")
        self.hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hint.setWordWrap(True)

        self.drop_panel = QFrame()
        self.drop_panel.setObjectName("dropPanel")
        self.drop_panel.setProperty("dragActive", False)
        self.drop_panel.setMinimumSize(520, 360)
        self.drop_panel.setMaximumSize(620, 400)

        content = QVBoxLayout(self.drop_panel)
        content.setContentsMargins(48, 36, 48, 36)
        content.setSpacing(0)
        content.addWidget(icon, 0, Qt.AlignmentFlag.AlignCenter)
        content.addSpacing(14)
        content.addWidget(self.title)
        content.addSpacing(8)
        content.addWidget(self.subtitle)
        content.addSpacing(26)
        content.addWidget(self.open_button, 0, Qt.AlignmentFlag.AlignCenter)
        content.addSpacing(14)
        content.addWidget(self.hint)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 48, 48, 48)
        layout.addWidget(self.drop_panel, 0, Qt.AlignmentFlag.AlignCenter)
        self._apply_palette()

    def _apply_palette(self) -> None:
        if self._updating_palette:
            return
        self._updating_palette = True
        palette = self.palette()
        window = palette.window().color()
        base = palette.base().color()
        text = palette.windowText().color()
        highlight = palette.highlight().color()
        highlighted_text = palette.highlightedText().color()
        panel = _mix_color(window, base, 0.42)
        border = _mix_color(panel, text, 0.16)
        secondary = _mix_color(panel, text, 0.66)
        drag_background = _mix_color(panel, highlight, 0.10)
        disabled_background = _mix_color(panel, text, 0.14)
        disabled_text = _mix_color(panel, text, 0.46)

        try:
            self.setStyleSheet(
                f"""
            QWidget#emptyState {{
                background-color: {window.name()};
            }}
            QFrame#dropPanel {{
                background-color: {panel.name()};
                border: 1px solid {border.name()};
                border-radius: 8px;
            }}
            QFrame#dropPanel[dragActive="true"] {{
                background-color: {drag_background.name()};
                border: 2px solid {highlight.name()};
            }}
            QLabel {{
                border: none;
                background: transparent;
                color: {text.name()};
                letter-spacing: 0;
            }}
            QLabel#emptyTitle {{
                font-size: 21px;
                font-weight: 600;
            }}
            QLabel#emptySubtitle, QLabel#emptyHint {{
                color: {secondary.name()};
                font-size: 14px;
            }}
            QPushButton#openIpaButton {{
                color: {highlighted_text.name()};
                background-color: {highlight.name()};
                border: 1px solid {highlight.name()};
                border-radius: 6px;
                min-width: 210px;
                min-height: 42px;
                padding: 0 20px;
                font-size: 14px;
                font-weight: 600;
                letter-spacing: 0;
            }}
            QPushButton#openIpaButton:hover {{
                background-color: {highlight.lighter(112).name()};
                border-color: {highlight.lighter(112).name()};
            }}
            QPushButton#openIpaButton:pressed {{
                background-color: {highlight.darker(112).name()};
                border-color: {highlight.darker(112).name()};
            }}
            QPushButton#openIpaButton:disabled {{
                color: {disabled_text.name()};
                background-color: {disabled_background.name()};
                border-color: {border.name()};
            }}
                """
            )
        finally:
            self._updating_palette = False

    def changeEvent(self, event: QEvent) -> None:
        super().changeEvent(event)
        if event.type() in (QEvent.Type.PaletteChange, QEvent.Type.ApplicationPaletteChange):
            self._apply_palette()

    def set_drag_active(self, active: bool) -> None:
        if self.property("dragActive") == active:
            return
        self.setProperty("dragActive", active)
        self.drop_panel.setProperty("dragActive", active)
        self.drop_panel.style().unpolish(self.drop_panel)
        self.drop_panel.style().polish(self.drop_panel)
        self.drop_panel.update()

    def set_loading(self, file_name: str | None) -> None:
        loading = file_name is not None
        self.title.setText("Analyzing IPA..." if loading else "Open an IPA to begin")
        self.subtitle.setText(
            file_name
            if loading
            else "Inspect signing, permissions, frameworks, and package contents."
        )
        self.open_button.setText("Analyzing..." if loading else "Choose IPA File...")
        self.open_button.setEnabled(not loading)
        self.hint.setText(
            "Reading package metadata..." if loading else "or drag and drop an .ipa file here"
        )


class MainWindow(QMainWindow):
    def __init__(self, initial_path: str | None = None) -> None:
        super().__init__()
        self.setWindowTitle("IPA Analyzer")
        self.resize(1180, 760)
        self.setMinimumSize(880, 600)
        self.setAcceptDrops(True)
        self._thread: QThread | None = None
        self._worker: AnalysisWorker | None = None
        self._export_thread: QThread | None = None
        self._export_worker: ImageExportWorker | None = None
        self._closing = False
        self._pending_path: str | None = None
        self._has_result = False
        self._current_ipa_path = ""

        app_icon = QIcon(str(APP_ICON_PATH))
        if not app_icon.isNull():
            self.setWindowIcon(app_icon)

        self.open_action = QAction("Open IPA...", self)
        self.open_action.setShortcut(QKeySequence.StandardKey.Open)
        self.open_action.setToolTip("Open IPA")
        self.open_action.triggered.connect(self.open_ipa)
        self.export_images_action = QAction("Extract Image Files...", self)
        self.export_images_action.setToolTip(
            "Extract standalone image files from the current IPA"
        )
        self.export_images_action.setEnabled(False)
        self.export_images_action.triggered.connect(self.export_images)
        file_menu = self.menuBar().addMenu("&File")
        file_menu.addAction(self.open_action)
        file_menu.addSeparator()
        file_menu.addAction(self.export_images_action)

        self.empty_state = EmptyState()
        self.empty_state.open_requested.connect(self.open_ipa)

        self.navigation = QListWidget()
        self.stack = QStackedWidget()
        self.pages: list[tuple[str, QWidget]] = [
            ("Overview", OverviewPage()),
            ("iTunes Metadata", ITunesMetadataPage()),
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

        self.open_another_button = QPushButton("Open Another IPA...")
        self.open_another_button.setMinimumHeight(34)
        self.open_another_button.clicked.connect(self.open_action.trigger)
        self.open_action.changed.connect(
            lambda: self.open_another_button.setEnabled(self.open_action.isEnabled())
        )

        self.export_images_button = QPushButton("Extract Image Files...")
        self.export_images_button.setMinimumHeight(34)
        self.export_images_button.setToolTip(
            "Extract standalone image files from the current IPA"
        )
        self.export_images_button.setEnabled(False)
        self.export_images_button.clicked.connect(self.export_images_action.trigger)
        self.export_images_action.changed.connect(
            lambda: self.export_images_button.setEnabled(
                self.export_images_action.isEnabled()
            )
        )

        self.sidebar = QWidget()
        self.sidebar.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(8, 8, 8, 10)
        sidebar_layout.setSpacing(8)
        sidebar_layout.addWidget(self.navigation, 1)
        sidebar_layout.addWidget(self.export_images_button)
        sidebar_layout.addWidget(self.open_another_button)

        self.analysis_view = QWidget()
        layout = QHBoxLayout(self.analysis_view)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack, 1)

        self.content_stack = QStackedWidget()
        self.content_stack.addWidget(self.empty_state)
        self.content_stack.addWidget(self.analysis_view)
        self.content_stack.setCurrentWidget(self.empty_state)
        self.setCentralWidget(self.content_stack)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedWidth(130)
        self.progress.hide()
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().showMessage("No IPA loaded")
        self.statusBar().setVisible(False)

        if initial_path:
            QTimer.singleShot(0, lambda: self.load_ipa(initial_path))

    @Slot()
    def open_ipa(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open IPA", "", "IPA files (*.ipa)")
        if path:
            self.load_ipa(path)

    @Slot()
    def export_images(self) -> None:
        if not self._current_ipa_path:
            return
        if self._thread and self._thread.isRunning():
            self.statusBar().showMessage("Wait for the current analysis to finish")
            return
        if self._export_thread and self._export_thread.isRunning():
            return

        initial_directory = QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.DownloadLocation
        ) or str(Path(self._current_ipa_path).parent)
        parent = QFileDialog.getExistingDirectory(
            self,
            "Choose Where to Create the Extracted Images Folder",
            initial_directory,
        )
        if not parent:
            return

        folder_name = f"{Path(self._current_ipa_path).stem} Images"
        destination = self._available_directory(Path(parent), folder_name)
        self.open_action.setEnabled(False)
        self.export_images_action.setEnabled(False)
        self.statusBar().setVisible(True)
        self.progress.show()
        self.statusBar().showMessage(
            f"Extracting image files from {Path(self._current_ipa_path).name}..."
        )

        thread = QThread(self)
        worker = ImageExportWorker(self._current_ipa_path, str(destination))
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._image_export_completed)
        worker.failed.connect(self._image_export_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)
        worker.failed.connect(worker.deleteLater)
        thread.finished.connect(self._export_thread_finished)
        self._export_thread = thread
        self._export_worker = worker
        thread.start()

    @staticmethod
    def _available_directory(parent: Path, name: str) -> Path:
        candidate = parent / name
        number = 2
        while candidate.exists():
            candidate = parent / f"{name} {number}"
            number += 1
        return candidate

    def load_ipa(self, path: str) -> None:
        if self._export_thread and self._export_thread.isRunning():
            self._pending_path = path
            self.statusBar().showMessage(f"Queued {Path(path).name}")
            return
        if self._thread and self._thread.isRunning():
            self._pending_path = path
            self.statusBar().showMessage(f"Queued {Path(path).name}")
            return
        self.open_action.setEnabled(False)
        self.export_images_action.setEnabled(False)
        self.empty_state.set_drag_active(False)
        if not self._has_result:
            self.empty_state.set_loading(Path(path).name)
            self.content_stack.setCurrentWidget(self.empty_state)
        self.statusBar().setVisible(True)
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
        self._has_result = True
        self._current_ipa_path = result.ipa_path
        self.empty_state.set_loading(None)
        self.content_stack.setCurrentWidget(self.analysis_view)
        self.statusBar().setVisible(True)
        self.statusBar().showMessage(f"Analysis complete{warning_text}")
        self.progress.hide()
        self.open_action.setEnabled(True)
        self.export_images_action.setEnabled(
            self._thread is None or not self._thread.isRunning()
        )

    @Slot(str)
    def _analysis_failed(self, message: str) -> None:
        self.empty_state.set_loading(None)
        if not self._has_result:
            self.content_stack.setCurrentWidget(self.empty_state)
            self.statusBar().setVisible(False)
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
        self.export_images_action.setEnabled(bool(self._current_ipa_path))
        if self._closing:
            self.close()
        elif self._pending_path:
            path = self._pending_path
            self._pending_path = None
            QTimer.singleShot(0, lambda: self.load_ipa(path))

    @Slot(object)
    def _image_export_completed(self, result: ImageExtractionResult) -> None:
        self.progress.hide()
        if result.file_count == 0:
            self.statusBar().showMessage("No standalone image files found")
            if not self._closing:
                QMessageBox.information(
                    self,
                    "Extract Image Files",
                    "No standalone image files were found in this IPA.",
                )
            return

        self.statusBar().showMessage(
            f"Extracted {result.file_count} image file(s)"
        )
        if not self._closing:
            QMessageBox.information(
                self,
                "Extract Image Files",
                (
                    f"Extracted {result.file_count} image file(s) "
                    f"({format_bytes(result.total_size)}) to:\n\n{result.destination}"
                ),
            )

    @Slot(str)
    def _image_export_failed(self, message: str) -> None:
        self.progress.hide()
        self.statusBar().showMessage("Image extraction failed")
        if not self._closing:
            QMessageBox.critical(self, "Extract Image Files", message)

    @Slot()
    def _export_thread_finished(self) -> None:
        if self._export_thread:
            self._export_thread.deleteLater()
        self._export_thread = None
        self._export_worker = None
        self.open_action.setEnabled(True)
        self.export_images_action.setEnabled(bool(self._current_ipa_path))
        if self._closing:
            self.close()
        elif self._pending_path:
            path = self._pending_path
            self._pending_path = None
            QTimer.singleShot(0, lambda: self.load_ipa(path))

    def dragEnterEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        if any(url.isLocalFile() and url.toLocalFile().lower().endswith(".ipa") for url in urls):
            self.empty_state.set_drag_active(True)
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        self.empty_state.set_drag_active(False)
        event.accept()

    def dropEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        self.empty_state.set_drag_active(False)
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if url.isLocalFile() and path.lower().endswith(".ipa"):
                self.load_ipa(path)
                event.acceptProposedAction()
                return
        event.ignore()

    def closeEvent(self, event: QCloseEvent) -> None:
        analysis_running = bool(self._thread and self._thread.isRunning())
        export_running = bool(self._export_thread and self._export_thread.isRunning())
        if analysis_running or export_running:
            self._closing = True
            task = "analysis" if analysis_running else "image extraction"
            self.statusBar().showMessage(f"Waiting for the current {task} to finish...")
            event.ignore()
            return
        event.accept()
