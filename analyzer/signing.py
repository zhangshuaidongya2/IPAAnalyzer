from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .plist import PlistError, loads_plist
from .utils import CommandResult, run_command


def _combined_output(command: CommandResult) -> str:
    return "\n".join(part for part in (command.stdout, command.stderr) if part)


def _parse_key_values(output: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    authorities: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "Authority":
            authorities.append(value)
        elif key in {
            "Identifier",
            "TeamIdentifier",
            "Format",
            "CodeDirectory",
            "Signature",
            "Timestamp",
            "Info.plist entries",
        }:
            parsed[key] = value
    parsed["Authority"] = authorities
    return parsed


def _extract_xml_plist(output: str) -> dict[str, Any]:
    start = output.find("<?xml")
    if start < 0:
        start = output.find("<plist")
    end = output.rfind("</plist>")
    if start < 0 or end < start:
        raise PlistError("codesign output did not contain an XML plist")
    return loads_plist(output[start : end + len("</plist>")])


def analyze_code_signature(
    bundle_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[str]]:
    details_command = run_command(["codesign", "-d", "--verbose=4", str(bundle_path)])
    entitlements_command = run_command(
        ["codesign", "-d", "--entitlements", ":-", str(bundle_path)]
    )

    errors: list[str] = []
    details = _parse_key_values(_combined_output(details_command))
    details["valid_structure"] = details_command.succeeded
    entitlements: dict[str, Any] = {}
    if entitlements_command.succeeded:
        try:
            entitlements = _extract_xml_plist(_combined_output(entitlements_command))
        except PlistError as exc:
            errors.append(f"Code signature entitlements parse failed: {exc}")
    else:
        detail = entitlements_command.stderr.strip() or "unknown error"
        errors.append(f"Code signature entitlements unavailable: {detail}")

    if not details_command.succeeded:
        detail = details_command.stderr.strip() or "unknown error"
        errors.append(f"Code signature inspection failed: {detail}")

    raw = {
        "details": details_command.to_dict(),
        "entitlements": entitlements_command.to_dict(),
    }
    return details, entitlements, raw, errors


def classify_signing(
    profile: dict[str, Any],
    code_signature: dict[str, Any],
    macho: dict[str, Any] | None = None,
    *,
    profile_present: bool,
) -> dict[str, Any]:
    evidence: list[str] = []
    profile_entitlements = profile.get("Entitlements", {}) or {}
    devices = profile.get("ProvisionedDevices")
    all_devices = profile.get("ProvisionsAllDevices") is True
    get_task_allow = profile_entitlements.get("get-task-allow") is True
    signed = code_signature.get("valid_structure") is True
    encrypted = bool((macho or {}).get("encrypted"))

    if profile_present:
        evidence.append("embedded.mobileprovision is present")
    if devices:
        evidence.append(f"ProvisionedDevices contains {len(devices)} device(s)")
    if all_devices:
        evidence.append("ProvisionsAllDevices is true")
    if get_task_allow:
        evidence.append("get-task-allow is true")
    if signed:
        evidence.append("codesign recognized a code signature")
    if encrypted:
        evidence.append("Mach-O cryptid indicates FairPlay encryption")

    profile_decoded = bool(profile)
    if profile_present and profile_decoded and all_devices:
        signing_type = "Enterprise"
    elif profile_present and profile_decoded and devices and get_task_allow:
        signing_type = "Development"
    elif profile_present and profile_decoded and devices:
        signing_type = "Ad Hoc"
    elif profile_present and profile_decoded and not devices and not all_devices and not get_task_allow:
        signing_type = "App Store"
    elif not profile_present and signed and encrypted:
        signing_type = "App Store"
    else:
        signing_type = "Unknown"
        evidence.append("Available indicators are insufficient for a reliable classification")

    team_ids = profile.get("TeamIdentifier") or []
    if isinstance(team_ids, str):
        team_ids = [team_ids]
    team_id = (
        (team_ids[0] if team_ids else "")
        or code_signature.get("TeamIdentifier", "")
        or profile_entitlements.get("com.apple.developer.team-identifier", "")
    )
    return {
        "type": signing_type,
        "team_id": team_id,
        "profile_name": profile.get("Name", ""),
        "profile_uuid": profile.get("UUID", ""),
        "creation_date": profile.get("CreationDate"),
        "expiration_date": profile.get("ExpirationDate"),
        "evidence": evidence,
        "code_signature": code_signature,
    }
