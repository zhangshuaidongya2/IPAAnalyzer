from __future__ import annotations

from typing import Any


PERMISSION_KEYS = (
    ("Camera", "NSCameraUsageDescription"),
    ("Microphone", "NSMicrophoneUsageDescription"),
    ("Photo Library", "NSPhotoLibraryUsageDescription"),
    ("Add Photos", "NSPhotoLibraryAddUsageDescription"),
    ("Location When In Use", "NSLocationWhenInUseUsageDescription"),
    ("Location Always", "NSLocationAlwaysUsageDescription"),
    ("Location Always and When In Use", "NSLocationAlwaysAndWhenInUseUsageDescription"),
    ("Bluetooth", "NSBluetoothAlwaysUsageDescription"),
    ("Bluetooth Peripheral", "NSBluetoothPeripheralUsageDescription"),
    ("Contacts", "NSContactsUsageDescription"),
    ("Calendars", "NSCalendarsUsageDescription"),
    ("Reminders", "NSRemindersUsageDescription"),
    ("Motion", "NSMotionUsageDescription"),
    ("Health Share", "NSHealthShareUsageDescription"),
    ("Health Update", "NSHealthUpdateUsageDescription"),
    ("Face ID", "NSFaceIDUsageDescription"),
    ("Speech Recognition", "NSSpeechRecognitionUsageDescription"),
    ("Local Network", "NSLocalNetworkUsageDescription"),
    ("Tracking", "NSUserTrackingUsageDescription"),
)


def analyze_permissions(info: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "permission": name,
            "key": key,
            "declared": key in info,
            "description": info.get(key, ""),
        }
        for name, key in PERMISSION_KEYS
    ]


def analyze_url_schemes(
    info: dict[str, Any], entitlements: dict[str, Any] | None = None
) -> dict[str, list[str]]:
    registered: list[str] = []
    for url_type in info.get("CFBundleURLTypes", []) or []:
        if isinstance(url_type, dict):
            registered.extend(str(item) for item in url_type.get("CFBundleURLSchemes", []) or [])

    query = [str(item) for item in info.get("LSApplicationQueriesSchemes", []) or []]
    associated = []
    if entitlements:
        associated = [
            str(item)
            for item in entitlements.get("com.apple.developer.associated-domains", []) or []
        ]
    return {
        "registered": list(dict.fromkeys(registered)),
        "query_schemes": list(dict.fromkeys(query)),
        "associated_domains": list(dict.fromkeys(associated)),
    }
