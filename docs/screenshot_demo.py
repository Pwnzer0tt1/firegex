#!/usr/bin/env python3
"""
Take the README's screenshot of the interface, from the demo build.

Usage:
    python3 docs/screenshot_demo.py [url] [output_path]

`url` defaults to the published demo; the release workflow builds the demo from the
release being published and serves it locally instead, so the picture is of that version
and not of whatever the Pages deploy last finished (built with `VITE_VERSION=<tag>`, the
header then names it instead of saying "demo"). Needs Playwright with chromium
(`pip install playwright && playwright install --with-deps chromium`).

The viewport is fixed, so the image keeps its size from one release to the next however
much the demo's seed data happens to render.
"""
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

URL = sys.argv[1] if len(sys.argv) > 1 else "https://demo.firegex.pwnzer0tt1.it/"
OUTPUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).parent / "Firegex_Screenshot.png"
VIEWPORT = {"width": 1600, "height": 960}


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport=VIEWPORT, device_scale_factor=2, color_scheme="dark")
        page.goto(URL, wait_until="networkidle")
        # The demo greets its visitor with a toast saying it is one, which is not part of
        # the interface being pictured.
        page.add_style_tag(content=".mantine-Notifications-root { display: none !important; }")
        # The list fills in from the demo's in-memory backend after the page has loaded;
        # a seeded service's name is what says it has.
        page.wait_for_selector("text=shop-api", timeout=15000)
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUTPUT))
        browser.close()
    print(f"Saved {OUTPUT} ({VIEWPORT['width']}x{VIEWPORT['height']} @2x)")


if __name__ == "__main__":
    main()
