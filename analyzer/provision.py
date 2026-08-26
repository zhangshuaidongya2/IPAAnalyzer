from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

from .plist import PlistError, loads_plist
from .utils import CommandResult, run_command


PROFILE_FIELDS = (
    "Name",
    "UUID",
    "TeamName",
    "TeamIdentifier",
    "AppIDName",
    "ApplicationIdentifierPrefix",
    "CreationDate",
    "ExpirationDate",
    "Platform",
    "ProvisionedDevices",
    "ProvisionsAllDevices",
)


def decode_mobileprovision(path: Path) -> tuple[dict[str, Any], CommandResult, list[str]]:
    command = run_command(["security", "cms", "-D", "-i", str(path)])
    if not command.succeeded:
        detail = command.stderr.strip() or command.stdout.strip() or "unknown error"
        return {}, command, [f"Provisioning profile decode failed: {detail}"]
    try:
        return loads_plist(command.stdout), command, []
    except PlistError as exc:
        return {}, command, [f"Provisioning profile parse failed: {exc}"]


def summarize_provision(profile: dict[str, Any], *, present: bool) -> dict[str, Any]:
    summary = {field: profile.get(field) for field in PROFILE_FIELDS}
    devices = profile.get("ProvisionedDevices")
    summary.update(
        {
            "present": present,
            "device_count": len(devices) if isinstance(devices, list) else 0,
            "entitlements": profile.get("Entitlements", {}),
            "certificate_count": len(profile.get("DeveloperCertificates", []) or []),
        }
    )
    return summary


def _openssl_value(lines: list[str], prefix: str) -> str:
    prefix_lower = prefix.lower()
    for line in lines:
        if line.lower().startswith(prefix_lower):
            return line.split("=", 1)[1].strip() if "=" in line else line[len(prefix) :].strip()
    return ""


def analyze_certificate(certificate: bytes, index: int) -> tuple[dict[str, Any], dict[str, Any]]:
    command = run_command(
        [
            "openssl",
            "x509",
            "-inform",
            "DER",
            "-noout",
            "-subject",
            "-issuer",
            "-serial",
            "-dates",
            "-nameopt",
            "RFC2253",
        ],
        input_data=certificate,
    )
    lines = [line.strip() for line in command.stdout.splitlines() if line.strip()]
    result = {
        "index": index,
        "subject": _openssl_value(lines, "subject="),
        "issuer": _openssl_value(lines, "issuer="),
        "serial_number": _openssl_value(lines, "serial="),
        "sha1_fingerprint": hashlib.sha1(certificate).hexdigest().upper(),
        "sha256_fingerprint": hashlib.sha256(certificate).hexdigest().upper(),
        "not_before": _openssl_value(lines, "notBefore="),
        "not_after": _openssl_value(lines, "notAfter="),
        "parsed": command.succeeded,
    }
    return result, command.to_dict()


def analyze_certificates(profile: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    results: list[dict[str, Any]] = []
    raw_commands: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, item in enumerate(profile.get("DeveloperCertificates", []) or [], start=1):
        if not isinstance(item, bytes):
            errors.append(f"Developer certificate {index} is not DER data")
            continue
        result, raw = analyze_certificate(item, index)
        results.append(result)
        raw_commands.append(raw)
        if not result["parsed"]:
            errors.append(f"Developer certificate {index} could not be parsed by openssl")
    return results, raw_commands, errors


def is_profile_expired(profile: dict[str, Any]) -> bool | None:
    expiration = profile.get("ExpirationDate")
    if not isinstance(expiration, datetime):
        return None
    now = datetime.now(tz=expiration.tzinfo) if expiration.tzinfo else datetime.now()
    return expiration < now
