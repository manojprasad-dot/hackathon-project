"""
PhishGuard -- features/threat_intelligence.py
Threat feed checker: downloads and caches OpenPhish and PhishTank feeds.

Runs a background refresh thread every 6 hours.
Thread-safe access to feed sets via threading.Lock.
"""

import logging
import threading
import time
from typing import Dict, Any, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """
    Downloads known-phishing URL feeds and provides fast in-memory lookups.

    Feeds:
      - OpenPhish (free feed): one URL per line
      - PhishTank (online-valid): JSON array of phishing entries

    Also supports a local blocklist managed via admin API.
    """

    REFRESH_INTERVAL_SECONDS = 6 * 60 * 60  # 6 hours

    def __init__(self, auto_start: bool = True) -> None:
        self._lock = threading.Lock()
        self.openphish_urls: Set[str] = set()
        self.phishtank_urls: Set[str] = set()
        self.local_blocklist: Set[str] = set()
        self._running = False

        if auto_start:
            self.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background refresh daemon thread."""
        if self._running:
            return
        self._running = True
        t = threading.Thread(target=self._background_loop, daemon=True,
                             name="ThreatIntel-Refresh")
        t.start()
        logger.info("Threat intelligence background thread started")

    def stop(self) -> None:
        """Signal the background thread to stop."""
        self._running = False

    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check whether *url* (or its domain) appears in any feed.

        Returns:
            {
                "in_openphish": bool,
                "in_phishtank": bool,
                "in_local_blocklist": bool,
                "feed_match": str | None,   # name of the matching feed
                "is_known_phishing": bool,
            }
        """
        normalised = self._normalize_url(url)
        domain = self._extract_domain(url)

        with self._lock:
            in_op = normalised in self.openphish_urls or domain in self.openphish_urls
            in_pt = normalised in self.phishtank_urls or domain in self.phishtank_urls
            in_bl = normalised in self.local_blocklist or domain in self.local_blocklist

        feed_match: Optional[str] = None
        if in_op:
            feed_match = "OpenPhish"
        elif in_pt:
            feed_match = "PhishTank"
        elif in_bl:
            feed_match = "LocalBlocklist"

        return {
            "in_openphish": in_op,
            "in_phishtank": in_pt,
            "in_local_blocklist": in_bl,
            "feed_match": feed_match,
            "is_known_phishing": in_op or in_pt or in_bl,
        }

    def add_to_blocklist(self, url: str) -> None:
        """Add a URL to the local blocklist."""
        with self._lock:
            self.local_blocklist.add(self._normalize_url(url))

    def remove_from_blocklist(self, url: str) -> None:
        """Remove a URL from the local blocklist."""
        with self._lock:
            self.local_blocklist.discard(self._normalize_url(url))

    def get_blocklist(self) -> list:
        """Return a copy of the local blocklist."""
        with self._lock:
            return sorted(self.local_blocklist)

    # ------------------------------------------------------------------
    # Feed refresh
    # ------------------------------------------------------------------

    def refresh_feeds(self) -> None:
        """Download all feeds and replace in-memory sets atomically."""
        new_openphish = self._fetch_openphish()
        new_phishtank = self._fetch_phishtank()

        with self._lock:
            self.openphish_urls = new_openphish
            self.phishtank_urls = new_phishtank

        logger.info(
            f"Threat feeds refreshed — OpenPhish: {len(new_openphish)}, "
            f"PhishTank: {len(new_phishtank)}"
        )

        # Update feed status in database (best-effort)
        try:
            from database import update_feed_status
            update_feed_status("OpenPhish", len(new_openphish),
                               "active" if new_openphish else "error")
            update_feed_status("PhishTank", len(new_phishtank),
                               "active" if new_phishtank else "error")
        except Exception as exc:
            logger.debug(f"Could not update feed status in DB: {exc}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _background_loop(self) -> None:
        """Periodically refresh feeds until stopped."""
        while self._running:
            try:
                self.refresh_feeds()
            except Exception as exc:
                logger.warning(f"Threat feed refresh error: {exc}")
            # Sleep in small intervals so we can stop quickly
            for _ in range(self.REFRESH_INTERVAL_SECONDS):
                if not self._running:
                    break
                time.sleep(1)

    def _fetch_openphish(self) -> Set[str]:
        """Download the OpenPhish community feed (plain-text, one URL per line)."""
        urls: Set[str] = set()
        try:
            import requests
            resp = requests.get(
                "https://openphish.com/feed.txt",
                timeout=30,
                headers={"User-Agent": "PhishGuard/1.0"},
            )
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if line and line.startswith("http"):
                    urls.add(self._normalize_url(line))
        except Exception as exc:
            logger.warning(f"OpenPhish feed download failed: {exc}")
        return urls

    def _fetch_phishtank(self) -> Set[str]:
        """Download the PhishTank online-valid feed (JSON)."""
        urls: Set[str] = set()
        try:
            import requests
            resp = requests.get(
                "http://data.phishtank.com/data/online-valid.json",
                timeout=60,
                headers={"User-Agent": "PhishGuard/1.0"},
            )
            resp.raise_for_status()
            data = resp.json()
            for entry in data:
                raw_url = entry.get("url", "")
                if raw_url:
                    urls.add(self._normalize_url(raw_url))
        except Exception as exc:
            logger.warning(f"PhishTank feed download failed: {exc}")
        return urls

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Lowercase, strip trailing slashes and 'www.' prefix."""
        url = url.lower().rstrip("/")
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host.startswith("www."):
            host = host[4:]
        # Reconstruct with cleaned host
        path = parsed.path.rstrip("/")
        return f"{parsed.scheme}://{host}{path}"

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract bare domain (without www.) from a URL."""
        try:
            parsed = urlparse(url.lower())
            host = parsed.hostname or ""
            if host.startswith("www."):
                host = host[4:]
            return host
        except Exception:
            return ""
