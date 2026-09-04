"""Optional UI smoke test: open the dashboard in a headless browser, check the key views render, and save screenshots.

Usage:  python scripts/ui_smoke.py [http://127.0.0.1:8787] [docs/screenshots]
Needs:  pip install playwright && python -m playwright install chromium   (skipped gracefully otherwise)
"""
from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8787"
    out = Path(sys.argv[2] if len(sys.argv) > 2 else "docs/screenshots")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright not installed. To run this smoke test:\n"
              "  pip install playwright && python -m playwright install chromium\n"
              f"then start the server (ecdat serve out/) and re-run: python scripts/ui_smoke.py {url}")
        return 0
    out.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(url, wait_until="networkidle", timeout=30000)
        page.wait_for_selector("text=ALREADY EXPOSED", timeout=15000)
        page.screenshot(path=str(out / "overview.png"), full_page=True)
        exposed_before = page.locator(".tier-card.EXPOSED .big").inner_text()
        for tab in ("matrix", "assets", "plan"):
            page.get_by_role("button", name=tab, exact=True).click()
            page.wait_for_timeout(400)
            page.screenshot(path=str(out / f"{tab}.png"), full_page=True)
        page.get_by_role("button", name="overview", exact=True).click()
        # Z slider: aggressive preset should not decrease the EXPOSED count
        page.get_by_role("button", name="aggressive", exact=True).click()
        page.wait_for_timeout(1500)
        exposed_after = page.locator(".tier-card.EXPOSED .big").inner_text()
        if page.locator("text=MOCK DATA").count() == 0 and int(exposed_after) < int(exposed_before):
            failures.append(f"EXPOSED count fell from {exposed_before} to {exposed_after} at an earlier Z")
        page.screenshot(path=str(out / "overview-z2032.png"), full_page=True)
        browser.close()
    if failures:
        print("FAIL:", *failures, sep="\n  ")
        return 1
    print(f"ok: screenshots in {out} (EXPOSED {exposed_before} -> {exposed_after} at Z=2032)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
