"""Helper module imported by sample_module.py for import-hop tests."""


def escape_html(value: str) -> str:
    """Escape HTML special characters in a string."""
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def validate_url(url: str) -> bool:
    """Allowlist-based URL validation."""
    return url.startswith("https://trusted.example.com/")
