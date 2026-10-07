"""
threat_intel.py - Threat-intelligence IP feeds merged with the static blacklist.

:class:`ThreatIntelManager` downloads public IP blocklists (by default the
Emerging Threats "compromised IPs" list and the abuse.ch Feodo Tracker botnet
C2 list), caches them in ``data/threat_feeds/`` and returns the combined
entries for :class:`detection_engine.RuleBasedDetector`.

Fallback order per feed
-----------------------
1. **Fresh cache** - a cached copy younger than ``cache_ttl_hours`` is used
   without touching the network (skipped with ``force_update=True`` /
   ``--update-feeds``).
2. **Network** - download the feed and refresh the cache.
3. **Stale cache** - if the download fails, an older cached copy is used.
4. **Static only** - if nothing is available the feed is skipped; the static
   ``RuleConfig.blacklisted_ips`` list always remains active.

A failure is never fatal: it is recorded in :attr:`ThreatIntelManager.status`.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from config import CONFIG, AppConfig, ThreatFeedConfig

logger = logging.getLogger("network_anomaly_detector.threat_intel")

#: Signature of a feed downloader: ``(url, timeout_seconds) -> text``.
Fetcher = Callable[[str, float], str]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FeedStatus:
    """Outcome of loading one feed.

    Attributes:
        name: Feed name.
        origin: ``network``, ``cache``, ``stale-cache``, ``local`` or ``unavailable``.
        entries: Number of valid IP/CIDR entries loaded.
        age_hours: Age of the cached copy used (None if not from cache).
        error: Error message for failed downloads (None on success).
    """

    name: str
    origin: str
    entries: int
    age_hours: Optional[float] = None
    error: Optional[str] = None


def parse_feed(text: str) -> List[str]:
    """Extract valid IPs / CIDR blocks from a plain-text blocklist.

    Blank lines and comments (``#`` or ``;``) are skipped. Only the first
    token of each line is considered, so ``1.2.3.4 # note`` and
    ``1.2.3.4,extra`` both work. Invalid tokens are ignored.
    """
    entries: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        token = line.replace(",", " ").replace("\t", " ").split()[0]
        try:
            entries.append(str(ipaddress.ip_network(token, strict=False)))
        except ValueError:
            continue
    return entries


def _requests_fetcher(url: str, timeout: float) -> str:
    """Default downloader using :mod:`requests` (imported lazily)."""
    import requests  # local import: requests is only needed when downloading

    response = requests.get(url, timeout=timeout,
                            headers={"User-Agent": "network-anomaly-detector/2.0"})
    response.raise_for_status()
    return response.text


# --------------------------------------------------------------------------- #
# Manager
# --------------------------------------------------------------------------- #
class ThreatIntelManager:
    """Loads, caches and merges threat-intelligence IP feeds.

    Args:
        config: Application configuration (``config.threat_feeds`` and
            ``config.rules.blacklisted_ips`` are used).
        fetcher: Optional downloader ``(url, timeout) -> text``; defaults to
            :mod:`requests`. Tests inject a fake to avoid network access.
    """

    def __init__(self, config: AppConfig = CONFIG, fetcher: Optional[Fetcher] = None) -> None:
        self.cfg: ThreatFeedConfig = config.threat_feeds
        self.static_blacklist = tuple(config.rules.blacklisted_ips)
        self.fetcher: Fetcher = fetcher or _requests_fetcher
        self.status: List[FeedStatus] = []
        self.entries: Dict[str, str] = {}

    # ------------------------------------------------------------------ #
    def cache_path(self, name: str) -> Path:
        """Location of the cached copy of feed ``name``."""
        return Path(self.cfg.cache_dir) / f"{name}.txt"

    def _cache_age_hours(self, path: Path) -> Optional[float]:
        """Age of ``path`` in hours, or None if it does not exist."""
        if not path.is_file():
            return None
        return max(0.0, (time.time() - path.stat().st_mtime) / 3600.0)

    def _load_feed(self, name: str, url: str, force_update: bool) -> List[str]:
        """Load one remote feed following the fallback order; records a :class:`FeedStatus`."""
        path = self.cache_path(name)
        age = self._cache_age_hours(path)
        if not force_update and age is not None and age < self.cfg.cache_ttl_hours:
            entries = parse_feed(path.read_text(encoding="utf-8", errors="replace"))
            self.status.append(FeedStatus(name, "cache", len(entries), round(age, 2)))
            return entries

        try:
            text = self.fetcher(url, self.cfg.request_timeout_seconds)
            entries = parse_feed(text)
            if not entries:
                raise ValueError("feed contained no valid IP entries")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            self.status.append(FeedStatus(name, "network", len(entries)))
            logger.info("Downloaded threat feed %s (%d entries)", name, len(entries))
            return entries
        except Exception as exc:  # noqa: BLE001 - any failure falls back to the cache
            error = f"{type(exc).__name__}: {exc}"[:200]
            logger.warning("Could not download threat feed %s: %s", name, error)

        if age is not None:
            entries = parse_feed(path.read_text(encoding="utf-8", errors="replace"))
            self.status.append(FeedStatus(name, "stale-cache", len(entries), round(age, 2), error))
            return entries
        self.status.append(FeedStatus(name, "unavailable", 0, None, error))
        return []

    def load(self, force_update: bool = False) -> Dict[str, str]:
        """Load every configured feed and return ``{ip_or_cidr: feed_name}``.

        Static blacklist entries are *not* included (they are already handled
        by :class:`detection_engine.RuleBasedDetector` and keep their
        ``BLACKLISTED_IP`` alert type). Use :meth:`merged_blacklist` for the
        combined view.

        Args:
            force_update: Ignore the cache TTL and try to download every feed.
        """
        self.status = []
        self.entries = {}
        if not self.cfg.enabled:
            return {}
        for name, url in self.cfg.feed_urls:
            for entry in self._load_feed(name, url, force_update):
                self.entries.setdefault(entry, name)
        for local in self.cfg.local_feed_files:
            local = Path(local)
            try:
                entries = parse_feed(local.read_text(encoding="utf-8", errors="replace"))
                self.status.append(FeedStatus(local.stem, "local", len(entries)))
            except OSError as exc:
                entries = []
                self.status.append(FeedStatus(local.stem, "unavailable", 0, None, str(exc)))
            for entry in entries:
                self.entries.setdefault(entry, local.stem)
        static = {str(ipaddress.ip_network(e, strict=False)) for e in self.static_blacklist}
        self.entries = {e: n for e, n in self.entries.items() if e not in static}
        return dict(self.entries)

    def update_feeds(self) -> Dict[str, str]:
        """Force a download of every feed (``--update-feeds``)."""
        return self.load(force_update=True)

    def merged_blacklist(self) -> Dict[str, str]:
        """Static blacklist plus loaded feed entries as ``{entry: source}``."""
        merged = {str(ipaddress.ip_network(e, strict=False)): "static" for e in self.static_blacklist}
        for entry, name in self.entries.items():
            merged.setdefault(entry, name)
        return merged

    def summary(self) -> str:
        """One-line, human-readable summary of the last :meth:`load`."""
        if not self.cfg.enabled:
            return "Threat intel disabled (static blacklist only)."
        if not self.status:
            return "Threat intel not loaded."
        parts = []
        for s in self.status:
            age = f", {s.age_hours:.1f}h old" if s.age_hours is not None else ""
            parts.append(f"{s.name}: {s.entries} ({s.origin}{age})")
        fallback = "" if self.entries else " - using static blacklist only"
        return f"Threat intel: {len(self.entries)} feed entries [{'; '.join(parts)}]{fallback}"


if __name__ == "__main__":  # pragma: no cover - manual smoke test
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    manager = ThreatIntelManager()
    manager.update_feeds()
    print(manager.summary())
