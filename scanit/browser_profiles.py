"""Shared browser-profile discovery for built-in checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class BrowserProfile:
    browser: str
    family: str
    path: Path


def discover_browser_profiles(home: Path) -> list[BrowserProfile]:
    chromium_roots = (
        ("brave", home / ".config/BraveSoftware/Brave-Browser"),
        ("chromium", home / ".config/chromium"),
        ("chrome", home / ".config/google-chrome"),
        ("brave", home / ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"),
        ("chromium", home / ".var/app/org.chromium.Chromium/config/chromium"),
        ("chrome", home / ".var/app/com.google.Chrome/config/google-chrome"),
    )
    profiles: set[BrowserProfile] = set()
    for browser, root in chromium_roots:
        if not root.is_dir():
            continue
        for candidate in root.iterdir():
            if candidate.is_dir() and (candidate / "Preferences").is_file():
                profiles.add(BrowserProfile(browser, "chromium", candidate))

    firefox_roots = (
        home / ".mozilla/firefox",
        home / ".var/app/org.mozilla.firefox/.mozilla/firefox",
    )
    for root in firefox_roots:
        if not root.is_dir():
            continue
        for candidate in root.iterdir():
            if candidate.is_dir() and (candidate / "prefs.js").is_file():
                profiles.add(BrowserProfile("firefox", "firefox", candidate))
    return sorted(profiles, key=lambda profile: str(profile.path))
