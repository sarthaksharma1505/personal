"""URL validation utility for the Fintech Threat Detection Agent."""

import re
from urllib.parse import urlparse


class InvalidURLError(ValueError):
    """Raised when a URL is invalid or not a proper web address."""
    pass


# Matches a valid domain: labels separated by dots, TLD at least 2 chars
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def validate_url(url: str) -> str:
    """Validate and normalize a user-provided URL.

    Checks that the input is a valid web URL (not random text, a file path,
    a number, an email, etc.). Returns the normalized URL with scheme.

    Raises:
        InvalidURLError: If the input is not a valid URL.
    """
    if not url or not isinstance(url, str):
        raise InvalidURLError("URL cannot be empty.")

    url = url.strip()
    if not url:
        raise InvalidURLError("URL cannot be empty.")

    # Reject obviously non-URL inputs
    if " " in url and not url.startswith(("http://", "https://")):
        raise InvalidURLError(
            f"Invalid URL: '{url}'. Please enter a valid website address "
            f"(e.g., example.com or https://example.com)."
        )

    # Reject unsupported schemes early (before adding https://)
    if "://" in url and not url.startswith(("http://", "https://")):
        scheme = url.split("://")[0]
        raise InvalidURLError(
            f"Invalid URL scheme: '{scheme}'. Only http and https are supported."
        )

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    # Must have a hostname
    hostname = parsed.hostname
    if not hostname:
        raise InvalidURLError(
            f"Invalid URL: '{url}'. No hostname found. "
            f"Please enter a valid website address (e.g., example.com)."
        )

    # Reject localhost / loopback for security
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        raise InvalidURLError(
            f"Invalid URL: '{hostname}' is a local address. "
            f"Please enter a public website address."
        )

    # Reject IP addresses without a domain name (basic check)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        raise InvalidURLError(
            f"Invalid URL: '{hostname}' is an IP address. "
            f"Please enter a domain name (e.g., example.com)."
        )

    # Validate domain format - must have at least one dot and valid TLD
    if not _DOMAIN_RE.match(hostname):
        raise InvalidURLError(
            f"Invalid URL: '{hostname}' is not a valid domain name. "
            f"Please enter a valid website address (e.g., example.com or https://example.com)."
        )

    return url
