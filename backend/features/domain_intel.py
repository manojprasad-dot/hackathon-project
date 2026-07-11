"""
PhishGuard -- features/domain_intel.py
Domain intelligence utilities: WHOIS age, SSL certificate checks,
homograph / leet-speak detection, and URL shortener expansion.

All functions include in-memory caching with TTL to avoid repeated network calls.
"""

import ssl
import socket
import logging
import time
import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# In-memory TTL cache
# ---------------------------------------------------------------------------

class _TTLCache:
    """Simple thread-safe cache with per-key TTL."""

    def __init__(self, default_ttl: int = 3600) -> None:
        self._store: Dict[str, Tuple[Any, float]] = {}
        self._default_ttl = default_ttl

    def get(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires = entry
        if time.time() > expires:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        ttl = ttl or self._default_ttl
        self._store[key] = (value, time.time() + ttl)


_domain_age_cache = _TTLCache(default_ttl=7 * 24 * 3600)   # 7 days
_ssl_cache = _TTLCache(default_ttl=3600)                     # 1 hour
_homograph_cache = _TTLCache(default_ttl=86400)              # 24 hours
_shortener_cache = _TTLCache(default_ttl=3600)               # 1 hour


# ---------------------------------------------------------------------------
# Domain age (WHOIS)
# ---------------------------------------------------------------------------

def get_domain_age(domain: str) -> Dict[str, Any]:
    """
    Look up the domain creation date via python-whois.

    Returns:
        {
            "age_days": int (-1 on error),
            "creation_date": str (ISO format or 'unknown'),
            "is_new": bool (True if age < 30 days),
        }
    """
    cached = _domain_age_cache.get(domain)
    if cached is not None:
        return cached

    result: Dict[str, Any] = {
        "age_days": -1,
        "creation_date": "unknown",
        "is_new": False,
    }

    try:
        import whois  # python-whois
        w = whois.whois(domain)
        creation = w.creation_date

        # Some registrars return a list
        if isinstance(creation, list):
            creation = creation[0]

        if creation is not None:
            if isinstance(creation, str):
                creation = datetime.fromisoformat(creation)

            # Make both TZ-aware for comparison
            now = datetime.now(timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)

            age_days = (now - creation).days
            result = {
                "age_days": age_days,
                "creation_date": creation.isoformat(),
                "is_new": age_days < 30,
            }
    except Exception as exc:
        logger.debug(f"WHOIS lookup failed for {domain}: {exc}")

    _domain_age_cache.set(domain, result)
    return result


# ---------------------------------------------------------------------------
# SSL certificate check
# ---------------------------------------------------------------------------

# Known free / automated CAs
_FREE_CAS = {
    "let's encrypt", "letsencrypt", "zerossl", "buypass",
    "ssl.com free", "google trust services", "sectigo (free)",
    "cloudflare", "amazon", "e1", "r3", "r10", "r11",
}


def check_ssl(domain: str) -> Dict[str, Any]:
    """
    Connect to *domain*:443 and inspect the TLS certificate.

    Returns:
        {
            "valid": bool,
            "issuer": str,
            "self_signed": bool,
            "days_to_expiry": int,
            "free_ca": bool,
        }
    """
    cached = _ssl_cache.get(domain)
    if cached is not None:
        return cached

    result: Dict[str, Any] = {
        "valid": False,
        "issuer": "unknown",
        "self_signed": False,
        "days_to_expiry": -1,
        "free_ca": False,
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        if cert:
            # Issuer
            issuer_parts = []
            for rdn in cert.get("issuer", ()):
                for attr_type, attr_val in rdn:
                    if attr_type in ("organizationName", "commonName"):
                        issuer_parts.append(attr_val)
            issuer_str = " / ".join(issuer_parts) if issuer_parts else "unknown"

            # Subject
            subject_parts = []
            for rdn in cert.get("subject", ()):
                for attr_type, attr_val in rdn:
                    if attr_type in ("organizationName", "commonName"):
                        subject_parts.append(attr_val)

            # Expiry
            not_after_str = cert.get("notAfter", "")
            days_to_expiry = -1
            if not_after_str:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_to_expiry = (not_after - datetime.utcnow()).days

            # Self-signed heuristic: subject == issuer
            self_signed = (set(subject_parts) == set(issuer_parts) and len(issuer_parts) > 0)

            # Free CA detection
            issuer_lower = issuer_str.lower()
            free_ca = any(fca in issuer_lower for fca in _FREE_CAS)

            result = {
                "valid": True,
                "issuer": issuer_str,
                "self_signed": self_signed,
                "days_to_expiry": days_to_expiry,
                "free_ca": free_ca,
            }

    except ssl.SSLCertVerificationError:
        result["valid"] = False
        result["self_signed"] = True
    except Exception as exc:
        logger.debug(f"SSL check failed for {domain}: {exc}")

    _ssl_cache.set(domain, result)
    return result


# ---------------------------------------------------------------------------
# Homograph / leet-speak detection
# ---------------------------------------------------------------------------

# Cyrillic → Latin confusable mapping
_CYRILLIC_MAP: Dict[str, str] = {
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р → p
    "\u0441": "c",  # с
    "\u0445": "x",  # х
    "\u0443": "y",  # у
    "\u043d": "h",  # н
    "\u0456": "i",  # і
    "\u0455": "s",  # ѕ
}

# Leet-speak → Latin mapping
_LEET_MAP: Dict[str, str] = {
    "0": "o",
    "1": "l",
    "!": "i",
    "3": "e",
    "5": "s",
    "4": "a",
    "8": "b",
    "@": "a",
    "$": "s",
    "7": "t",
    "9": "g",
    "|": "l",
}

_BRAND_LIST = [
    "google", "facebook", "apple", "microsoft", "amazon",
    "paypal", "netflix", "instagram", "twitter", "linkedin",
    "chase", "wellsfargo", "citibank", "bank", "ebay",
    "dropbox", "yahoo", "outlook", "coinbase", "binance",
    "uber", "spotify", "discord", "steam", "whatsapp",
    "telegram", "snapchat", "tiktok", "reddit", "venmo",
]


def detect_homograph(domain: str) -> Dict[str, Any]:
    """
    Detect Unicode confusable characters and leet-speak brand impersonation.

    Returns:
        {
            "is_homograph": bool,
            "target_brand": str,
            "similarity_score": float (0.0 – 1.0),
            "confusable_chars": list[str],
            "is_leet": bool,
        }
    """
    cached = _homograph_cache.get(domain)
    if cached is not None:
        return cached

    result: Dict[str, Any] = {
        "is_homograph": False,
        "target_brand": "",
        "similarity_score": 0.0,
        "confusable_chars": [],
        "is_leet": False,
    }

    # Strip TLD for analysis
    parts = domain.split(".")
    name = parts[0] if parts else domain

    # 1. Check for Cyrillic confusables
    confusable_chars: List[str] = []
    latin_equivalent = []
    for ch in name:
        if ch in _CYRILLIC_MAP:
            confusable_chars.append(ch)
            latin_equivalent.append(_CYRILLIC_MAP[ch])
        else:
            latin_equivalent.append(ch)
    latinised = "".join(latin_equivalent)

    # 2. Check for leet-speak
    deleet = []
    is_leet = False
    for ch in name:
        if ch in _LEET_MAP:
            deleet.append(_LEET_MAP[ch])
            is_leet = True
        elif ch in _CYRILLIC_MAP:
            deleet.append(_CYRILLIC_MAP[ch])
        else:
            deleet.append(ch)
    deleeted = "".join(deleet)

    # 3. Compare against brand list
    best_brand = ""
    best_score = 0.0

    for brand in _BRAND_LIST:
        for candidate in (latinised, deleeted, name):
            score = _similarity(candidate, brand)
            if score > best_score:
                best_score = score
                best_brand = brand

    # Threshold: 0.75 similarity to qualify as homograph
    if best_score >= 0.75 and (confusable_chars or is_leet):
        result = {
            "is_homograph": True,
            "target_brand": best_brand,
            "similarity_score": round(best_score, 3),
            "confusable_chars": confusable_chars,
            "is_leet": is_leet,
        }
    elif best_score >= 0.85:
        # Very high similarity even without confusables (typosquatting)
        result = {
            "is_homograph": True,
            "target_brand": best_brand,
            "similarity_score": round(best_score, 3),
            "confusable_chars": confusable_chars,
            "is_leet": is_leet,
        }

    _homograph_cache.set(domain, result)
    return result


def _similarity(a: str, b: str) -> float:
    """Compute normalised Levenshtein similarity between two strings."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    len_a, len_b = len(a), len(b)
    max_len = max(len_a, len_b)

    # Levenshtein distance (dynamic programming)
    dp = list(range(len_b + 1))
    for i in range(1, len_a + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, len_b + 1):
            temp = dp[j]
            if a[i - 1] == b[j - 1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(dp[j], dp[j - 1], prev)
            prev = temp

    distance = dp[len_b]
    return round(1.0 - distance / max_len, 4)


# ---------------------------------------------------------------------------
# URL shortener expansion
# ---------------------------------------------------------------------------

_SHORTENING_SERVICES = {
    "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "j.mp", "tr.im",
    "rb.gy", "cutt.ly", "shorturl.at", "v.gd", "clck.ru",
    "tny.im", "su.pr", "lnkd.in", "db.tt", "qr.ae",
    "bc.vc", "x.co", "tiny.cc", "s.id", "rotf.lol",
    "shorturl.asia", "u.to", "t.ly", "soo.gd", "qps.ru",
    "rebrand.ly", "bl.ink", "short.io", "tnurl.co",
}


def expand_shortened_url(url: str) -> Dict[str, Any]:
    """
    If *url* uses a known shortening service, follow redirects to find the
    final destination URL.

    Returns:
        {
            "is_shortened": bool,
            "original_url": str,
            "final_url": str,
            "redirect_count": int,
        }
    """
    cached = _shortener_cache.get(url)
    if cached is not None:
        return cached

    result: Dict[str, Any] = {
        "is_shortened": False,
        "original_url": url,
        "final_url": url,
        "redirect_count": 0,
    }

    try:
        parsed = urlparse(url.lower())
        host = parsed.hostname or ""
        if host.startswith("www."):
            host = host[4:]

        if host not in _SHORTENING_SERVICES:
            _shortener_cache.set(url, result)
            return result

        result["is_shortened"] = True

        import requests
        resp = requests.head(
            url,
            allow_redirects=True,
            timeout=5,
            headers={"User-Agent": "PhishGuard/1.0"},
        )
        result["final_url"] = resp.url
        result["redirect_count"] = len(resp.history)

    except Exception as exc:
        logger.debug(f"Shortened URL expansion failed for {url}: {exc}")

    _shortener_cache.set(url, result)
    return result
