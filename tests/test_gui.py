from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QPoint, Qt
    from PySide6.QtTest import QSignalSpy, QTest
    from PySide6.QtWidgets import QApplication, QLineEdit, QStyleOptionViewItem

    PYSIDE_AVAILABLE = True
except ImportError:
    QApplication = None  # type: ignore[assignment,misc]
    PYSIDE_AVAILABLE = False

from models import IPAAnalysisResult


@unittest.skipUnless(PYSIDE_AVAILABLE, "PySide6 is not installed")
class GUISmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from ui.main_window import EmptyState, MainWindow

        cls.app = QApplication.instance() or QApplication([])
        cls.empty_state_class = EmptyState
        cls.window_class = MainWindow

    def test_empty_state_interactions(self) -> None:
        empty_state = self.empty_state_class()
        open_spy = QSignalSpy(empty_state.open_requested)

        empty_state.open_button.click()
        self.assertEqual(open_spy.count(), 1)

        empty_state.set_loading("Example.ipa")
        self.assertEqual(empty_state.title.text(), "Analyzing IPA...")
        self.assertEqual(empty_state.subtitle.text(), "Example.ipa")
        self.assertEqual(empty_state.hint.text(), "Reading package metadata...")
        self.assertFalse(empty_state.open_button.isEnabled())

        empty_state.set_drag_active(True)
        self.assertTrue(empty_state.property("dragActive"))

    def test_files_page_shows_recursive_directory_sizes(self) -> None:
        from analyzer.files import build_file_index
        from ui.main_window import FilesPage

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Folder" / "Nested").mkdir(parents=True)
            (root / "Folder" / "Empty").mkdir()
            (root / "Folder" / "file.bin").write_bytes(b"a" * 1024)
            (root / "Folder" / "Nested" / "data.bin").write_bytes(b"b" * 2048)
            result = IPAAnalysisResult(ipa_path="sample.ipa", files=build_file_index(root))

        page = FilesPage()
        self.addCleanup(page.close)
        page.set_result(result)
        folder = page.tree.topLevelItem(0)
        self.assertEqual(folder.text(1), "3.00 KB")
        children = {folder.child(i).text(0): folder.child(i) for i in range(folder.childCount())}
        self.assertEqual(children["Empty"].text(1), "0 B")
        self.assertEqual(children["file.bin"].text(1), "1.00 KB")
        self.assertEqual(children["Nested"].text(1), "2.00 KB")
        self.assertEqual(children["Nested"].child(0).text(1), "2.00 KB")

    def test_framework_size_header_cycles_sort_order(self) -> None:
        from ui.main_window import FrameworksPage

        frameworks = [
            {"name": "Medium", "size": 2048},
            {"name": "Large", "size": 1024 * 1024},
            {"name": "Small", "size": 900},
            {"name": "Tie", "size": 2048},
            {"name": "Larger", "size": 2049},
        ]
        original_names = [item["name"] for item in frameworks]
        page = FrameworksPage()
        self.addCleanup(page.close)
        page.resize(900, 500)
        page.set_result(IPAAnalysisResult(ipa_path="sample.ipa", frameworks=frameworks))
        page.show()
        self.app.processEvents()
        header = page.table.horizontalHeader()

        def row_names() -> list[str]:
            return [page.table.item(row, 0).text() for row in range(page.table.rowCount())]

        def click_header(column: int) -> None:
            position = QPoint(
                header.sectionViewportPosition(column) + header.sectionSize(column) // 2,
                header.height() // 2,
            )
            QTest.mouseClick(header.viewport(), Qt.MouseButton.LeftButton, pos=position)
            self.app.processEvents()

        self.assertEqual(row_names(), original_names)
        self.assertFalse(header.isSortIndicatorShown())
        page.table.setCurrentCell(3, 3)
        descending = ["Large", "Larger", "Medium", "Tie", "Small"]
        ascending = ["Small", "Medium", "Tie", "Larger", "Large"]
        for expected, order in (
            (descending, Qt.SortOrder.DescendingOrder),
            (ascending, Qt.SortOrder.AscendingOrder),
            (original_names, None),
            (descending, Qt.SortOrder.DescendingOrder),
        ):
            with self.subTest(order=order):
                click_header(3)
                self.assertEqual(row_names(), expected)
                self.assertEqual(header.isSortIndicatorShown(), order is not None)
                if order is not None:
                    self.assertEqual(header.sortIndicatorSection(), 3)
                    self.assertEqual(header.sortIndicatorOrder(), order)
                self.assertEqual(page.table.currentRow(), -1)
                self.assertEqual(page.details.text.toPlainText(), "")
                page.table.setCurrentCell(expected.index("Tie"), 3)
                self.assertEqual(json.loads(page.details.text.toPlainText()), frameworks[3])
                click_header(0)
                self.assertEqual(row_names(), expected)
                self.assertEqual(header.isSortIndicatorShown(), order is not None)
                if order is not None:
                    self.assertEqual(header.sortIndicatorSection(), 3)
                    self.assertEqual(header.sortIndicatorOrder(), order)

        self.assertEqual([item["name"] for item in frameworks], original_names)
        page.table.setCurrentCell(0, 0)
        self.assertEqual(json.loads(page.details.text.toPlainText()), frameworks[1])

        replacement = [{"name": "New small", "size": 1}, {"name": "New large", "size": 4}]
        page.set_result(IPAAnalysisResult(ipa_path="new.ipa", frameworks=replacement))
        self.assertEqual(row_names(), ["New small", "New large"])
        self.assertFalse(header.isSortIndicatorShown())
        self.assertEqual(page.details.text.toPlainText(), "")
        click_header(3)
        self.assertEqual(row_names(), ["New large", "New small"])

        page.set_result(IPAAnalysisResult(ipa_path="empty.ipa"))
        for _ in range(3):
            click_header(3)
            self.assertEqual(page.table.rowCount(), 0)
        self.assertFalse(header.isSortIndicatorShown())

    def test_jctools_title_and_file_dialog_defaults(self) -> None:
        directory = Path("/tmp/下载目录 with spaces/jctoolsDownloads")
        window = self.window_class(title="IPA 分析 — JCTools", files_directory=directory)
        self.assertEqual(window.windowTitle(), "IPA 分析 — JCTools")
        with patch("ui.main_window.QFileDialog.getOpenFileName", return_value=("", "")) as choose:
            window.open_ipa()
            self.assertEqual(choose.call_args.args[2], str(directory))

        result = IPAAnalysisResult(
            ipa_path="/tmp/Example.ipa", basic={"display_name": "Example"},
            signing={"code_signature": {}}, entitlements={"effective": {}},
        )
        window._analysis_completed(result)
        self.assertEqual(window.windowTitle(), "Example - IPA 分析 — JCTools")
        self.assertEqual(window.navigation.count(), 11)
        with patch("ui.main_window.QFileDialog.getExistingDirectory", return_value="") as choose:
            window.export_images()
            self.assertEqual(choose.call_args.args[2], str(directory))
        self.assertTrue(window.export_images_action.isEnabled())
        window.close()

    def test_window_accepts_analysis_result(self) -> None:
        window = self.window_class()
        self.assertIs(window.content_stack.currentWidget(), window.empty_state)
        self.assertEqual(window.empty_state.title.text(), "Open an IPA to begin")
        self.assertEqual(window.empty_state.open_button.text(), "Choose IPA File...")
        self.assertTrue(window.statusBar().isHidden())
        self.assertFalse(window.windowIcon().isNull())
        self.assertFalse(window.export_images_action.isEnabled())
        self.assertFalse(window.export_images_button.isEnabled())

        result = IPAAnalysisResult(
            ipa_path="/tmp/example.ipa",
            basic={"display_name": "Example", "bundle_id": "com.example.app"},
            signing={"type": "Unknown", "code_signature": {}},
            entitlements={"effective": {}, "codesign": {}, "profile": {}},
            url_schemes={"registered": [], "query_schemes": [], "associated_domains": []},
            itunes_metadata={
                "itemName": "Example Store App",
                "artistName": "Example Developer",
                "itemId": 123456789,
            },
            size_info={"ipa_size": 10},
        )
        window._analysis_completed(result)
        self.app.processEvents()
        self.assertEqual(len(window.pages), 11)
        self.assertEqual(window.windowTitle(), "Example - IPA Analyzer")
        self.assertEqual(window.navigation.count(), 11)
        self.assertIs(window.content_stack.currentWidget(), window.analysis_view)
        self.assertEqual(window.open_another_button.text(), "Open Another IPA...")
        self.assertTrue(window.open_another_button.isEnabled())
        self.assertEqual(window.export_images_button.text(), "Extract Image Files...")
        self.assertTrue(window.export_images_action.isEnabled())
        self.assertTrue(window.export_images_button.isEnabled())
        self.assertFalse(window.statusBar().isHidden())

        metadata_page = dict(window.pages)["iTunes Metadata"]
        self.assertEqual(metadata_page.summary.item(1, 1).text(), "Example Store App")
        self.assertEqual(metadata_page.summary.item(6, 1).text(), "123456789")

        overview = window.pages[0][1]
        summary = overview.summary
        summary.setCurrentCell(0, 1)
        summary.item(0, 1).setSelected(True)
        self.assertTrue(summary.copy_selection())
        self.assertEqual(QApplication.clipboard().text(), "Example")

        index = summary.model().index(0, 1)
        editor = summary.itemDelegate().createEditor(
            summary.viewport(), QStyleOptionViewItem(), index
        )
        summary.itemDelegate().setEditorData(editor, index)
        self.app.processEvents()
        self.assertIsInstance(editor, QLineEdit)
        self.assertTrue(editor.isReadOnly())
        self.assertEqual(editor.selectedText(), "Example")
        window.close()


if __name__ == "__main__":
    unittest.main()
