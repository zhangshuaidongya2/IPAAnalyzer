from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
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
        from ui.main_window import MainWindow

        cls.app = QApplication.instance() or QApplication([])
        cls.window_class = MainWindow

    def test_window_accepts_analysis_result(self) -> None:
        window = self.window_class()
        result = IPAAnalysisResult(
            ipa_path="/tmp/example.ipa",
            basic={"display_name": "Example", "bundle_id": "com.example.app"},
            signing={"type": "Unknown", "code_signature": {}},
            entitlements={"effective": {}, "codesign": {}, "profile": {}},
            url_schemes={"registered": [], "query_schemes": [], "associated_domains": []},
            size_info={"ipa_size": 10},
        )
        window._analysis_completed(result)
        self.app.processEvents()
        self.assertEqual(len(window.pages), 10)
        self.assertEqual(window.windowTitle(), "Example - IPA Analyzer")
        self.assertEqual(window.navigation.count(), 10)

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
