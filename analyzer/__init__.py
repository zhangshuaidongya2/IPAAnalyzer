"""Static IPA analysis package."""

from .files import ImageExtractionResult, extract_image_resources
from .ipa import IPAAnalyzer, IPAAnalysisError

__all__ = [
    "IPAAnalyzer",
    "IPAAnalysisError",
    "ImageExtractionResult",
    "extract_image_resources",
]
