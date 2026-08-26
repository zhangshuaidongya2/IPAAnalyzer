from __future__ import annotations

import sys

from PySide6.QtCore import QCoreApplication, QEvent, QTimer, Signal
from PySide6.QtGui import QFileOpenEvent
from PySide6.QtWidgets import QApplication

from .main_window import MainWindow


class IPAApplication(QApplication):
    file_opened = Signal(str)

    def __init__(self, arguments: list[str]) -> None:
        self.pending_files: list[str] = []
        super().__init__(arguments)

    def event(self, event: QEvent) -> bool:
        if event.type() == QEvent.Type.FileOpen and isinstance(event, QFileOpenEvent):
            path = event.file()
            if path:
                self.pending_files.append(path)
                self.file_opened.emit(path)
                return True
        return super().event(event)


def run_gui(initial_path: str | None = None, *, quit_after_ms: int | None = None) -> int:
    QCoreApplication.setApplicationName("IPA Analyzer")
    QCoreApplication.setOrganizationName("IPA Analyzer")
    QCoreApplication.setOrganizationDomain("ipaanalyzer.app")
    app = QApplication.instance() or IPAApplication([sys.argv[0]])
    window = MainWindow(initial_path)

    def open_from_finder(path: str) -> None:
        window.load_ipa(path)
        window.show()
        window.raise_()
        window.activateWindow()

    if isinstance(app, IPAApplication):
        app.file_opened.connect(open_from_finder)
        pending = list(app.pending_files)
        app.pending_files.clear()
        if not initial_path and pending:
            QTimer.singleShot(0, lambda: open_from_finder(pending[-1]))

    window.show()
    window.raise_()
    window.activateWindow()
    QTimer.singleShot(
        0,
        lambda: window.windowHandle().requestActivate() if window.windowHandle() else None,
    )
    if quit_after_ms is not None:
        QTimer.singleShot(quit_after_ms, app.quit)
    return app.exec()
