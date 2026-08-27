from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from analyzer.files import ArchiveSecurityError, extract_image_resources


class ImageExtractionTests(unittest.TestCase):
    def test_detects_content_repairs_extensions_and_flattens_output(self) -> None:
        png = b"\x89PNG\r\n\x1a\n" + b"png-data"
        webp = b"RIFF\x0c\x00\x00\x00WEBPVP8 " + b"webp-data"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = root / "Mismatched Images.ipa"
            destination = root / "Mismatched Images"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/App.app/Images/wrong.png", webp)
                archive.writestr("Payload/App.app/Images/extensionless", png)
                archive.writestr("Payload/App.app/Images/duplicate.png", png)
                archive.writestr("Payload/App.app/Other/duplicate.png", png)
                archive.writestr("Payload/App.app/not-an-image.png", b"plain text")

            result = extract_image_resources(ipa, destination)

            self.assertEqual(result.file_count, 4)
            self.assertEqual(
                sorted(path.name for path in destination.iterdir()),
                ["duplicate-2.png", "duplicate.png", "extensionless.png", "wrong.webp"],
            )
            self.assertTrue(all(path.is_file() for path in destination.iterdir()))
            self.assertEqual((destination / "wrong.webp").read_bytes(), webp)
            self.assertFalse((destination / "not-an-image.png").exists())

    def test_extracts_supported_image_formats_and_ignores_other_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = root / "Example.ipa"
            destination = root / "Example Images"
            resources = {
                "Payload/Example.app/Icon.PNG": (
                    "Icon.PNG",
                    b"\x89PNG\r\n\x1a\n" + b"png-data",
                ),
                "Payload/Example.app/Images/photo.jpg": (
                    "photo.jpg",
                    b"\xff\xd8\xff" + b"jpeg-data",
                ),
                "Payload/Example.app/Artwork/vector.PDF": (
                    "vector.PDF",
                    b"%PDF-1.4\n" + b"pdf-data",
                ),
                "iTunesArtwork": (
                    "iTunesArtwork.png",
                    b"\x89PNG\r\n\x1a\n" + b"artwork-data",
                ),
            }
            with zipfile.ZipFile(ipa, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, (_, data) in resources.items():
                    archive.writestr(name, data)
                archive.writestr("Payload/Example.app/Assets.car", b"compiled-assets")
                archive.writestr("Payload/Example.app/readme.txt", b"not-an-image")

            result = extract_image_resources(ipa, destination)

            self.assertEqual(result.file_count, len(resources))
            self.assertEqual(
                result.total_size,
                sum(len(data) for _, data in resources.values()),
            )
            for output_name, data in resources.values():
                self.assertEqual((destination / output_name).read_bytes(), data)
            self.assertFalse((destination / "Assets.car").exists())
            self.assertFalse((destination / "readme.txt").exists())

    def test_no_images_does_not_create_an_empty_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = root / "No Images.ipa"
            destination = root / "No Images Images"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Example.app/Info.plist", b"plist")

            result = extract_image_resources(ipa, destination)

            self.assertEqual(result.file_count, 0)
            self.assertEqual(result.total_size, 0)
            self.assertFalse(destination.exists())

    def test_rejects_image_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = root / "Unsafe.ipa"
            destination = root / "Unsafe Images"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("../outside.png", b"bad")

            with self.assertRaisesRegex(ArchiveSecurityError, "Unsafe archive path"):
                extract_image_resources(ipa, destination)

            self.assertFalse(destination.exists())
            self.assertFalse((root / "outside.png").exists())


if __name__ == "__main__":
    unittest.main()
