from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any


def to_json_compatible(value: Any) -> Any:
    """Recursively convert plist and analysis values into JSON-safe values."""
    if isinstance(value, dict):
        return {str(key): to_json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_json_compatible(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, bytes):
        return "base64:" + base64.b64encode(value).decode("ascii")
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


@dataclass
class IPAAnalysisResult:
    ipa_path: str
    basic: dict[str, Any] = field(default_factory=dict)
    signing: dict[str, Any] = field(default_factory=dict)
    provision: dict[str, Any] = field(default_factory=dict)
    certificates: list[dict[str, Any]] = field(default_factory=list)
    entitlements: dict[str, Any] = field(default_factory=dict)
    permissions: list[dict[str, Any]] = field(default_factory=list)
    macho: dict[str, Any] = field(default_factory=dict)
    frameworks: list[dict[str, Any]] = field(default_factory=list)
    extensions: list[dict[str, Any]] = field(default_factory=list)
    embedded_bundles: list[dict[str, Any]] = field(default_factory=list)
    url_schemes: dict[str, list[str]] = field(default_factory=dict)
    files: list[dict[str, Any]] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)
    size_info: dict[str, int] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_json_compatible(asdict(self))

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
