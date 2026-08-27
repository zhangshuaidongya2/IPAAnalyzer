from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtTest import QSignalSpy
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
