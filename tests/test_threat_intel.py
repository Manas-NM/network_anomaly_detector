"""Tests for threat_intel.py using a fake downloader (no network access)."""

from __future__ import annotations

import os
import time
from dataclasses import replace
from pathlib import Path
from typing import Dict, List

import pytest

from threat_intel import ThreatIntelManager, parse_feed

FEEDS = (("alpha", "https://feeds.invalid/alpha.txt"), ("beta", "https://feeds.invalid/beta.txt"))
TEXT: Dict[str, str] = {
    FEEDS[0][1]: "# alpha feed\n45.9.9.9\n45.9.9.10 # trailing note\n\nnot-an-ip\n192.0.2.66\n",
    FEEDS[1][1]: "; beta\n100.64.0.0/24,botnet\n45.9.9.9\n",
}


class FakeFetcher:
    def __init__(self, fail: bool = False, texts: Dict[str, str] = TEXT) -> None:
        self.fail, self.texts = fail, texts
        self.calls: List[str] = []

    def __call__(self, url: str, timeout: float) -> str:
        self.calls.append(url)
        if self.fail:
            raise ConnectionError("network down")
        return self.texts[url]


@pytest.fixture
def config(isolated_config):
    return replace(isolated_config, threat_feeds=replace(isolated_config.threat_feeds, feed_urls=FEEDS))


def test_parse_feed() -> None:
    text = "# c\n; c\n1.2.3.4\n5.6.7.0/24 extra\n1.2.3.5,foo\n\tbad\n2001:db8::1\n10.0.0.1/8\n"
    assert parse_feed(text) == ["1.2.3.4/32", "5.6.7.0/24", "1.2.3.5/32", "2001:db8::1/128", "10.0.0.0/8"]


def test_download_merges_and_caches(config) -> None:
    fetcher = FakeFetcher()
    manager = ThreatIntelManager(config, fetcher=fetcher)
    entries = manager.load()
    # Static blacklist entry 192.0.2.66 is excluded; first feed wins for duplicates.
    assert entries == {"45.9.9.9/32": "alpha", "45.9.9.10/32": "alpha", "100.64.0.0/24": "beta"}
    assert [s.origin for s in manager.status] == ["network", "network"]
    assert manager.cache_path("alpha").is_file() and manager.cache_path("beta").is_file()
    assert "3 feed entries" in manager.summary()
    merged = manager.merged_blacklist()
    assert merged["192.0.2.66/32"] == "static" and merged["100.64.0.0/24"] == "beta"


def test_fresh_cache_skips_network_unless_forced(config) -> None:
    ThreatIntelManager(config, fetcher=FakeFetcher()).load()
    fetcher = FakeFetcher(fail=True)
    manager = ThreatIntelManager(config, fetcher=fetcher)
    assert len(manager.load()) == 3
    assert fetcher.calls == [] and {s.origin for s in manager.status} == {"cache"}

    ok = FakeFetcher()
    ThreatIntelManager(config, fetcher=ok).update_feeds()
    assert ok.calls == [u for _, u in FEEDS]


def test_stale_cache_fallback(config) -> None:
    manager = ThreatIntelManager(config, fetcher=FakeFetcher())
    manager.load()
    old = time.time() - 48 * 3600
    for name, _ in FEEDS:
        os.utime(manager.cache_path(name), (old, old))
    failing = ThreatIntelManager(config, fetcher=FakeFetcher(fail=True))
    assert len(failing.load()) == 3
    assert {s.origin for s in failing.status} == {"stale-cache"}
    assert all("network down" in s.error for s in failing.status)
    assert all(s.age_hours >= 47 for s in failing.status)


def test_no_cache_no_network_falls_back_to_static(config) -> None:
    manager = ThreatIntelManager(config, fetcher=FakeFetcher(fail=True))
    assert manager.load() == {}
    assert {s.origin for s in manager.status} == {"unavailable"}
    assert "static blacklist only" in manager.summary()
    assert "192.0.2.66/32" in manager.merged_blacklist()


def test_empty_feed_is_treated_as_failure(config) -> None:
    manager = ThreatIntelManager(config, fetcher=FakeFetcher(texts={u: "# nothing\n" for _, u in FEEDS}))
    assert manager.load() == {}
    assert not manager.cache_path("alpha").exists()


def test_disabled_and_local_files(config, tmp_path: Path) -> None:
    disabled = replace(config, threat_feeds=replace(config.threat_feeds, enabled=False))
    manager = ThreatIntelManager(disabled, fetcher=FakeFetcher())
    assert manager.load() == {} and "disabled" in manager.summary()

    local = tmp_path / "inhouse.txt"
    local.write_text("8.8.4.4\n")
    with_local = replace(config, threat_feeds=replace(config.threat_feeds, feed_urls=(),
                                                      local_feed_files=(local, tmp_path / "missing.txt")))
    manager = ThreatIntelManager(with_local, fetcher=FakeFetcher())
    assert manager.load() == {"8.8.4.4/32": "inhouse"}
    assert [s.origin for s in manager.status] == ["local", "unavailable"]
