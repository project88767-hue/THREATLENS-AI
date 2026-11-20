import ipaddress
import re
from urllib.parse import urlparse

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata",
    "kubernetes.default",
    "kubernetes.default.svc",
}

BLOCKED_DOMAIN_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
    ".corp",
    ".lan",
)

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


class SSRFBlockedError(ValueError):
    """Raised when an indicator targets restricted internal, loopback, or metadata infrastructure."""


def validate_public_ip(ip_str: str) -> str:
    cleaned = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 or IPv6 address: {cleaned}") from exc

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        raise SSRFBlockedError(
            f"SSRF Protection: Restricted non-public IP address '{cleaned}' cannot be scanned. "
            "THREATLENS AI only analyzes public indicators in authorized defensive workflows."
        )

    return str(ip_obj)


def validate_domain(domain_str: str) -> str:
    cleaned = domain_str.strip().lower().rstrip(".")
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        cleaned = (parsed.hostname or "").lower().rstrip(".")

    if not cleaned:
        raise ValueError("Domain cannot be empty.")

    if cleaned in BLOCKED_HOSTNAMES or cleaned.endswith(BLOCKED_DOMAIN_SUFFIXES):
        raise SSRFBlockedError(
            f"SSRF Protection: Internal or local hostname '{cleaned}' is blocked."
        )

    # Check if user passed an IP instead of domain
    try:
        ipaddress.ip_address(cleaned)
        raise ValueError("Expected a domain name, not a raw IP address.")
    except ValueError as exc:
        if "Expected a domain name" in str(exc):
            raise

    # Support punycode labels too
    ascii_domain = cleaned.encode("idna").decode("ascii")
    if not DOMAIN_REGEX.match(ascii_domain):
        raise ValueError(f"Invalid domain format: '{cleaned}'")

    return ascii_domain


def validate_and_normalize_url(raw_url: str) -> tuple[str, str, str | None]:
    """
    Validates URL scheme and host against SSRF rules.
    Returns (normalized_url, hostname, ip_if_literal).
    """
    candidate = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise SSRFBlockedError(
            f"Unsupported or unsafe URL scheme '{scheme}://'. Only http:// and https:// are permitted."
        )

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValueError("URL must include a valid hostname.")

    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(BLOCKED_DOMAIN_SUFFIXES):
        raise SSRFBlockedError(
            f"SSRF Protection: Local or internal URL host '{hostname}' is restricted."
        )

    ip_literal: str | None = None
    try:
        ip_literal = validate_public_ip(hostname)
    except SSRFBlockedError:
        raise
    except ValueError:
        # Not an IP literal; validate as domain
        validate_domain(hostname)

    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    port_suffix = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    normalized = f"{scheme}://{hostname}{port_suffix}{path}{query}"
    return normalized, hostname, ip_literal
