#!/usr/bin/env python3
"""Browser negative control for immediate/restore-safe Console localization."""
from __future__ import annotations

from pathlib import Path
import argparse
import os
import sys
import shutil

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
from smoke_ui import inline_document, prepare_page, browser_errors  # noqa: E402

AUTHORITY = "CONSOLE_LOCALIZATION_RUNTIME_V1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    with sync_playwright() as pw:
        chromium = os.environ.get("PLATFORM_FACTORY_UI_BROWSER_EXECUTABLE", "").strip() or shutil.which("chromium") or shutil.which("google-chrome") or pw.chromium.executable_path
        browser = pw.chromium.launch(headless=True, executable_path=chromium, args=["--no-sandbox"])
        context = browser.new_context(viewport={"width": 1280, "height": 900})
        page = context.new_page()
        errors = browser_errors(page)
        prepare_page(page, inline_document(root / "webconsole/static"), installer=False)

        initial = page.evaluate("""() => ({
          locale: state.locale,
          searchText: document.querySelector('#command-trigger span')?.textContent,
          searchAria: document.querySelector('#command-trigger')?.getAttribute('aria-label'),
          refreshAria: document.querySelector('#refresh-current')?.getAttribute('aria-label')
        })""")
        if initial != {
            "locale": "en",
            "searchText": "Search console",
            "searchAria": "Search console",
            "refreshAria": "Refresh current page",
        }:
            raise SystemExit(f"LOCALIZATION_RUNTIME_INITIAL_ENGLISH_INVALID {initial}")

        fa = page.evaluate("""() => {
          state.locale='fa';
          applyLocale();
          return {
            lang: document.documentElement.lang,
            dir: document.documentElement.dir,
            searchText: document.querySelector('#command-trigger span')?.textContent,
            searchAria: document.querySelector('#command-trigger')?.getAttribute('aria-label'),
            refreshAria: document.querySelector('#refresh-current')?.getAttribute('aria-label')
          };
        }""")
        expected_fa = {
            "lang": "fa",
            "dir": "rtl",
            "searchText": "جست‌وجوی پنل",
            "searchAria": "جست‌وجوی پنل",
            "refreshAria": "بازخوانی صفحه جاری",
        }
        if fa != expected_fa:
            raise SystemExit(f"LOCALIZATION_RUNTIME_FA_NOT_IMMEDIATE expected={expected_fa} actual={fa}")

        dynamic = page.evaluate("""() => {
          const button=document.createElement('button');
          button.textContent='Review next action';
          button.setAttribute('aria-label','Refresh current page');
          document.body.appendChild(button);
          return new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve({
            text: button.textContent,
            aria: button.getAttribute('aria-label')
          }))));
        }""")
        if dynamic != {"text": "بررسی اقدام بعدی", "aria": "بازخوانی صفحه جاری"}:
            raise SystemExit(f"LOCALIZATION_RUNTIME_MUTATION_NOT_LOCALIZED {dynamic}")

        restored = page.evaluate("""() => {
          state.locale='en';
          applyLocale();
          const button=[...document.body.querySelectorAll('button')].find(item=>item.textContent==='Review next action');
          return {
            lang: document.documentElement.lang,
            dir: document.documentElement.dir,
            searchText: document.querySelector('#command-trigger span')?.textContent,
            searchAria: document.querySelector('#command-trigger')?.getAttribute('aria-label'),
            refreshAria: document.querySelector('#refresh-current')?.getAttribute('aria-label'),
            dynamicText: button?.textContent,
            dynamicAria: button?.getAttribute('aria-label')
          };
        }""")
        expected_restore = {
            "lang": "en",
            "dir": "ltr",
            "searchText": "Search console",
            "searchAria": "Search console",
            "refreshAria": "Refresh current page",
            "dynamicText": "Review next action",
            "dynamicAria": "Refresh current page",
        }
        if restored != expected_restore:
            raise SystemExit(f"LOCALIZATION_RUNTIME_RESTORE_INVALID expected={expected_restore} actual={restored}")
        if errors:
            raise SystemExit("LOCALIZATION_RUNTIME_BROWSER_ERRORS " + " | ".join(errors))
        context.close(); browser.close()
    print(f"CONSOLE_LOCALIZATION_RUNTIME_PASS authority={AUTHORITY}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
