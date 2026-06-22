"""
Utility functions used across all scanner modules.
"""

import re
import validators
import logging
from urllib.parse import urlparse, urljoin

logger = logging.getLogger("phishguard.helpers")


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate and normalize a URL.
    Returns (is_valid, normalized_url_or_error_message)
    """
    if not url:
        return False, "URL cannot be empty"

    url = url.strip()

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Validate format
    if not validators.url(url):
        return False, f"Invalid URL format: {url}"

    # Block private/local IPs
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    private_patterns = [
        r"^localhost$",
        r"^127\.",
        r"^192\.168\.",
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"^0\.0\.0\.0$"
    ]
    for pattern in private_patterns:
        if re.match(pattern, hostname):
            return False, f"Private/local IP addresses not allowed: {hostname}"

    return True, url


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def get_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or ""
    except Exception:
        return ""


def is_external_url(base_url: str, target_url: str) -> bool:
    """Check if target_url is on a different domain than base_url."""
    try:
        base_domain   = urlparse(base_url).netloc
        target_domain = urlparse(target_url).netloc
        if not target_domain:
            return False
        return base_domain != target_domain
    except Exception:
        return False


def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text for logging."""
    return text[:max_length] + "..." if len(text) > max_length else text
