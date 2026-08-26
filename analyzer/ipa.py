from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path
from typing import Any

from models.result import IPAAnalysisResult

from .files import ArchiveSecurityError, build_file_index, safe_extract_ipa
from .frameworks import analyze_embedded_bundles, analyze_extensions, analyze_frameworks
from .macho import analyze_macho
from .permissions import analyze_permissions, analyze_url_schemes
from .plist import PlistError, extract_overview, load_plist, plist_xml
from .provision import analyze_certificates, decode_mobileprovision, summarize_provision
from .signing import analyze_code_signature, classify_signing
from .utils import directory_size, hash_file


class IPAAnalysisError(RuntimeError):
    pass


class IPAAnalyzer:
    def analyze(self, ipa_path: str | Path) -> IPAAnalysisResult:
        path = Path(ipa_path).expanduser().resolve()
        self._validate_input(path)
        result = IPAAnalysisResult(ipa_path=str(path))

        try:
            result.hashes = {
                f"ipa_{name}": value
                for name, value in hash_file(path, ("md5", "sha1", "sha256")).items()
            }
        except OSError as exc:
            raise IPAAnalysisError(f"Unable to read IPA: {exc}") from exc

        try:
            with zipfile.ZipFile(path, "r") as archive, tempfile.TemporaryDirectory(
                prefix="ipa-analyzer-"
            ) as temporary:
                extraction_root = Path(temporary)
                archive_size = sum(member.file_size for member in archive.infolist())
                safe_extract_ipa(
                    archive,
                    extraction_root,
                    warning=lambda message: result.errors.append(message),
                )
                self._analyze_extracted(
                    path, extraction_root, archive_size, result
                )
        except zipfile.BadZipFile as exc:
            raise IPAAnalysisError(f"Invalid or damaged IPA/ZIP file: {exc}") from exc
        except ArchiveSecurityError as exc:
            raise IPAAnalysisError(f"Unsafe IPA archive: {exc}") from exc
        return result

    @staticmethod
    def _validate_input(path: Path) -> None:
        if not path.exists():
            raise IPAAnalysisError(f"IPA file does not exist: {path}")
        if not path.is_file():
            raise IPAAnalysisError(f"IPA path is not a file: {path}")
        if path.suffix.lower() != ".ipa":
            raise IPAAnalysisError(f"Expected an .ipa file: {path}")

    def _analyze_extracted(
        self,
        ipa_path: Path,
        extraction_root: Path,
        archive_size: int,
        result: IPAAnalysisResult,
    ) -> None:
        app_path, candidates = self._find_main_app(extraction_root)
        info_path = app_path / "Info.plist"
        try:
            info = load_plist(info_path)
        except PlistError as exc:
            raise IPAAnalysisError(f"Main app Info.plist is invalid: {exc}") from exc

        result.basic = extract_overview(info)
        result.basic.update(
            {
                "ipa_name": ipa_path.name,
                "main_app_path": app_path.relative_to(extraction_root).as_posix(),
                "app_bundle_size": directory_size(app_path),
            }
        )
        result.raw["info_plist"] = info
        result.raw["info_plist_xml"] = plist_xml(info)
        result.raw["info_plist_source"] = info_path.read_bytes()
        result.raw["app_candidates"] = candidates

        profile_path = app_path / "embedded.mobileprovision"
        profile: dict[str, Any] = {}
        if profile_path.is_file():
            result.raw["mobileprovision_source"] = profile_path.read_bytes()
            profile, profile_command, profile_errors = decode_mobileprovision(profile_path)
            result.errors.extend(profile_errors)
            result.raw["mobileprovision_command"] = profile_command.to_dict()
        result.provision = summarize_provision(profile, present=profile_path.is_file())
        result.raw["mobileprovision"] = profile

        certificates, certificate_raw, certificate_errors = analyze_certificates(profile)
        result.certificates = certificates
        result.raw["certificate_commands"] = certificate_raw
        result.errors.extend(certificate_errors)

        signature, signed_entitlements, signature_raw, signature_errors = analyze_code_signature(
            app_path
        )
        result.errors.extend(signature_errors)
        profile_entitlements = profile.get("Entitlements", {}) or {}
        effective_entitlements = signed_entitlements or profile_entitlements
        result.entitlements = {
            "effective": effective_entitlements,
            "codesign": signed_entitlements,
            "profile": profile_entitlements,
        }
        result.raw["codesign"] = signature_raw
        result.raw["entitlements"] = {
            "codesign": signed_entitlements,
            "profile": profile_entitlements,
        }

        executable_name = result.basic.get("executable")
        executable = app_path / str(executable_name) if executable_name else None
        if executable and executable.is_file():
            macho, macho_raw, macho_errors = analyze_macho(executable)
            macho["path"] = executable.relative_to(extraction_root).as_posix()
            result.macho = macho
            result.raw["macho"] = macho_raw
            result.errors.extend(macho_errors)
            result.hashes["executable_sha256"] = hash_file(executable)["sha256"]
        else:
            result.macho = {}
            result.errors.append(
                f"Main executable is missing: {executable_name or 'CFBundleExecutable not set'}"
            )

        result.signing = classify_signing(
            profile,
            signature,
            result.macho,
            profile_present=profile_path.is_file(),
        )
        result.permissions = analyze_permissions(info)
        result.url_schemes = analyze_url_schemes(info, effective_entitlements)

        self._run_optional_modules(app_path, extraction_root, result)
        self._collect_sizes(
            ipa_path, app_path, executable, extraction_root, archive_size, result
        )

    @staticmethod
    def _find_main_app(extraction_root: Path) -> tuple[Path, list[dict[str, Any]]]:
        payload = extraction_root / "Payload"
        if not payload.is_dir():
            raise IPAAnalysisError("IPA does not contain a Payload directory")
        app_paths = sorted(
            (item for item in payload.iterdir() if item.is_dir() and item.suffix.lower() == ".app"),
            key=lambda item: item.name.lower(),
        )
        if not app_paths:
            raise IPAAnalysisError("Payload does not contain an app bundle")

        candidates: list[dict[str, Any]] = []
        for app in app_paths:
            info: dict[str, Any] = {}
            try:
                info = load_plist(app / "Info.plist")
            except PlistError:
                pass
            candidates.append(
                {
                    "path": app.relative_to(extraction_root).as_posix(),
                    "bundle_id": info.get("CFBundleIdentifier", ""),
                    "package_type": info.get("CFBundlePackageType", ""),
                    "is_watch_app": bool(info.get("WKWatchKitApp")),
                    "size": directory_size(app),
                }
            )

        viable = [
            (app, candidate)
            for app, candidate in zip(app_paths, candidates)
            if not candidate["is_watch_app"]
            and candidate["package_type"] in ("", "APPL")
        ]
        selected = max(viable or list(zip(app_paths, candidates)), key=lambda pair: pair[1]["size"])[0]
        return selected, candidates

    @staticmethod
    def _run_optional_modules(
        app_path: Path, extraction_root: Path, result: IPAAnalysisResult
    ) -> None:
        modules = (
            ("Framework analysis", "frameworks", analyze_frameworks),
            ("Extension analysis", "extensions", analyze_extensions),
            ("Embedded bundle analysis", "embedded_bundles", analyze_embedded_bundles),
        )
        for label, attribute, function in modules:
            try:
                setattr(result, attribute, function(app_path, extraction_root))
            except Exception as exc:
                result.errors.append(f"{label} failed: {exc}")
        result.raw["frameworks"] = [item.get("raw", {}) for item in result.frameworks]
        result.raw["extensions"] = [item.get("raw", {}) for item in result.extensions]
        result.raw["embedded_bundles"] = [
            item.get("raw", {}) for item in result.embedded_bundles
        ]
        try:
            result.files = build_file_index(extraction_root, Path(result.ipa_path))
        except Exception as exc:
            result.errors.append(f"File index failed: {exc}")

    @staticmethod
    def _collect_sizes(
        ipa_path: Path,
        app_path: Path,
        executable: Path | None,
        extraction_root: Path,
        archive_size: int,
        result: IPAAnalysisResult,
    ) -> None:
        frameworks_path = app_path / "Frameworks"
        framework_size = directory_size(frameworks_path) if frameworks_path.is_dir() else 0
        assets_size = sum(
            item.stat().st_size for item in app_path.rglob("Assets.car") if item.is_file()
        )
        excluded_roots = {"Frameworks", "PlugIns", "Watch", "AppClips"}
        resource_size = 0
        for item in app_path.rglob("*"):
            if not item.is_file() or item == executable:
                continue
            relative = item.relative_to(app_path)
            if relative.parts and relative.parts[0] in excluded_roots:
                continue
            resource_size += item.stat().st_size
        result.size_info = {
            "ipa_size": ipa_path.stat().st_size,
            "uncompressed_size": archive_size,
            "app_bundle_size": directory_size(app_path),
            "main_executable_size": executable.stat().st_size if executable and executable.is_file() else 0,
            "frameworks_total_size": framework_size,
            "resources_size": resource_size,
            "assets_car_size": assets_size,
        }
