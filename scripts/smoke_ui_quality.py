#!/usr/bin/env python3
"""Rendered UI quality gates for the Operator Console and Bootstrap Installer.

This is a stable owner-level verification suite. It adapts useful verification
ideas from public UX/UI agent guidance without importing a foreign design
system, runtime dependency, or agent harness.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SMOKE_SPEC = importlib.util.spec_from_file_location("platform_factory_smoke_ui", ROOT / "scripts" / "smoke_ui.py")
if SMOKE_SPEC is None or SMOKE_SPEC.loader is None:
    raise RuntimeError("unable to load smoke_ui owner helpers")
smoke_ui = importlib.util.module_from_spec(SMOKE_SPEC)
SMOKE_SPEC.loader.exec_module(smoke_ui)

CONSOLE_PAGES = [
    "overview", "workspace", "installation", "clusters", "providers", "blueprints", "marketplace", "baselines",
    "verification", "fleet", "tenants", "operations", "notifications", "services", "catalog", "validator",
]
INSTALLER_PAGES = ["overview", "installation", "progress", "health", "recovery", "lifecycle"]


def evidence_dir() -> Path:
    configured = os.environ.get("PLATFORM_FACTORY_SMOKE_EVIDENCE_DIR", "").strip()
    target = Path(configured).resolve() if configured else Path(tempfile.mkdtemp(prefix="4so-ui-quality-"))
    target.mkdir(parents=True, exist_ok=True)
    return target


def css_theme_reference_failures(css_path: Path) -> list[str]:
    text = css_path.read_text(encoding="utf-8")
    definitions = set(re.findall(r"--([A-Za-z0-9_-]+)\s*:", text))
    references = set(re.findall(r"var\(--([A-Za-z0-9_-]+)", text))
    return [f"undefined-css-token:{name}" for name in sorted(references - definitions)]


def static_quality_failures(root: Path) -> list[str]:
    failures: list[str] = []
    for rel in ("webconsole/static/styles.css", "cmd/platform-installer/static/styles.css"):
        failures.extend(f"{rel}:{item}" for item in css_theme_reference_failures(root / rel))
    for rel in ("webconsole/static/index.html", "cmd/platform-installer/static/index.html"):
        html = (root / rel).read_text(encoding="utf-8")
        lowered = html.lower()
        for phrase in ("welcome back", "congratulations", "glassmorphism"):
            if phrase in lowered:
                failures.append(f"{rel}:anti-slop-copy:{phrase}")
        if re.search(r'<button[^>]+(?:id="(?:mobile-nav-toggle|menu-toggle)"|aria-label="Close")[^>]*>\s*[☰×]\s*</button>', html, flags=re.I):
            failures.append(f"{rel}:raw-action-glyph")
        if 'class="hero"' in html:
            failures.append(f"{rel}:generic-admin-hero")
    return failures


DOM_AUDIT_JS = r"""() => {
  const visible = el => {
    const s = getComputedStyle(el), r = el.getBoundingClientRect();
    return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0;
  };
  const ids = [...document.querySelectorAll('[id]')].map(el => el.id);
  const duplicateIds = [...new Set(ids.filter((id, index) => ids.indexOf(id) !== index))];
  const unnamedActions = [...document.querySelectorAll('button,a[href],[role="button"]')].filter(visible).filter(el =>
    !String(el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.textContent || el.getAttribute('title') || '').trim()
  ).map(el => el.outerHTML.slice(0, 160));
  const unlabeledFields = [...document.querySelectorAll('input:not([type="hidden"]),select,textarea')].filter(visible).filter(el => {
    if (el.getAttribute('aria-label') || el.getAttribute('aria-labelledby')) return false;
    if (el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`)) return false;
    return !el.closest('label');
  }).map(el => el.outerHTML.slice(0, 160));
  const unnamedDialogs = [...document.querySelectorAll('dialog,[role="dialog"]')].filter(el =>
    !el.getAttribute('aria-label') && !el.getAttribute('aria-labelledby')
  ).map(el => el.outerHTML.slice(0, 160));
  const undersizedTargets = [...document.querySelectorAll('button,a[href],input,select,textarea,summary')].filter(visible).filter(el => {
    const r = el.getBoundingClientRect();
    return r.width < 24 || r.height < 24;
  }).map(el => ({tag:el.tagName,id:el.id,width:Math.round(el.getBoundingClientRect().width),height:Math.round(el.getBoundingClientRect().height)}));
  return {duplicateIds, unnamedActions, unlabeledFields, unnamedDialogs, undersizedTargets};
}"""

CONTRAST_JS = r"""el => {
  function rgba(value) {
    const match = String(value).match(/rgba?\(([^)]+)\)/);
    if (!match) return [0,0,0,0];
    const parts = match[1].split(',').map(v => parseFloat(v));
    return [parts[0], parts[1], parts[2], parts.length > 3 ? parts[3] : 1];
  }
  function composite(fg, bg) {
    const alpha = fg[3] + bg[3] * (1 - fg[3]);
    if (!alpha) return [0,0,0,0];
    return [0,1,2].map(i => (fg[i]*fg[3] + bg[i]*bg[3]*(1-fg[3]))/alpha).concat(alpha);
  }
  function luminance(color) {
    const values = color.slice(0,3).map(value => {
      const channel = value / 255;
      return channel <= .04045 ? channel / 12.92 : Math.pow((channel + .055) / 1.055, 2.4);
    });
    return .2126*values[0] + .7152*values[1] + .0722*values[2];
  }
  let layers = [], current = el;
  while (current) { layers.push(rgba(getComputedStyle(current).backgroundColor)); current = current.parentElement; }
  let background = [255,255,255,1];
  for (let index=layers.length-1; index>=0; index--) background = composite(layers[index], background);
  const foreground = rgba(getComputedStyle(el).color);
  const a=luminance(foreground), b=luminance(background);
  return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);
}"""


def audit_dom(page, label: str, failures: list[str]) -> None:
    result = page.evaluate(DOM_AUDIT_JS)
    for key, values in result.items():
        if values:
            failures.append(f"{label}:{key}:{values[:5]}")


def audit_contrast(page, label: str, failures: list[str]) -> None:
    selectors = [
        "#primary-nav button.active", "#section-nav button.active", "button.primary", "button.secondary",
        "button.danger", "button.link-button", "summary", ".badge",
    ]
    for selector in selectors:
        locator = page.locator(selector)
        for index in range(min(locator.count(), 6)):
            item = locator.nth(index)
            if not item.is_visible() or item.is_disabled():
                continue
            ratio = float(item.evaluate(CONTRAST_JS))
            if ratio < 4.5:
                text = (item.inner_text() or item.get_attribute("aria-label") or selector).strip()[:50]
                failures.append(f"{label}:contrast:{selector}:{ratio:.2f}:{text}")


def audit_console(browser, root: Path, failures: list[str]) -> None:
    document = smoke_ui.inline_document(root / "webconsole/static")
    # Narrow responsive + RTL mirrors beyond the legacy canonical set.
    for width in (280, 414):
        context = browser.new_context(viewport={"width": width, "height": 900})
        page = context.new_page()
        smoke_ui.prepare_page(page, document, installer=False)
        for route in CONSOLE_PAGES:
            page.evaluate("route => navigate(route)", route)
            page.wait_for_timeout(25)
            if page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 2"):
                failures.append(f"console:{width}:ltr-overflow:{route}")
        page.evaluate("document.querySelector('#language-toggle').click()")
        for route in CONSOLE_PAGES:
            page.evaluate("route => navigate(route)", route)
            page.wait_for_timeout(25)
            if page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 2"):
                failures.append(f"console:{width}:rtl-overflow:{route}")
        audit_dom(page, f"console:{width}:rtl", failures)
        context.close()

    # State, focus, a11y and contrast in both themes.
    for theme in ("light", "dark"):
        context = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme=theme)
        page = context.new_page()
        smoke_ui.prepare_page(page, document, installer=False)
        page.evaluate("() => navigate('operations')")
        page.wait_for_timeout(50)
        page.evaluate("""() => {
          const host=document.querySelector('#operation-grid');
          host.innerHTML=dataTable('Quality gate', [{label:'Operation'},{label:'Attempt',className:'numeric'}], [tableRow([tableCell('alpha'),tableCell('1','numeric')])], 'No operations', 'None', {source:'operations'});
        }""")
        shell = page.locator(".data-table-shell").first
        shell.focus()
        focus = shell.evaluate("el => { const s=getComputedStyle(el); return {style:s.outlineStyle,width:parseFloat(s.outlineWidth)||0,color:s.outlineColor}; }")
        if focus["style"] == "none" or focus["width"] < 2:
            failures.append(f"console:{theme}:data-table-focus-not-visible:{focus}")
        audit_dom(page, f"console:{theme}", failures)
        audit_contrast(page, f"console:{theme}", failures)
        feedback = page.evaluate("""() => {
          const originalSetTimeout = window.setTimeout, delays=[];
          window.setTimeout=(fn, delay, ...args)=>{delays.push(delay);return 1;};
          try {
            toast('quality error','error');
            const error=document.querySelector('#toast-region .toast.error');
            const errorButton=error?.querySelector('button[aria-label=\"Close\"]');
            const errorRawGlyph=(errorButton?.textContent||'').trim();
            const errorHasIcon=!!errorButton?.querySelector('svg use[href=\"#icon-close\"]');
            const errorScheduled=delays.includes(5200);
            error?.remove();
            delays.length=0;
            toast('quality success','success');
            const success=document.querySelector('#toast-region .toast.success');
            const successScheduled=delays.includes(5200);
            success?.remove();
            return {errorRawGlyph,errorHasIcon,errorScheduled,successScheduled};
          } finally { window.setTimeout=originalSetTimeout; }
        }""")
        if feedback.get("errorRawGlyph") or not feedback.get("errorHasIcon"):
            failures.append(f"console:{theme}:runtime-toast-action-icon:{feedback}")
        if feedback.get("errorScheduled") or not feedback.get("successScheduled"):
            failures.append(f"console:{theme}:toast-durability:{feedback}")
        context.close()

    # Real keyboard drawer trap and return-focus contract.
    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page()
    smoke_ui.prepare_page(page, document, installer=False)
    page.locator("#mobile-nav-toggle").click()
    page.keyboard.press("Shift+Tab")
    if page.evaluate("document.activeElement?.id") != "logout": failures.append("console:focus-trap:shift-tab")
    page.keyboard.press("Tab")
    if page.evaluate("document.activeElement?.dataset?.section") != "home": failures.append("console:focus-trap:tab-wrap")
    page.keyboard.press("Escape")
    if not page.evaluate("document.activeElement === document.querySelector('#mobile-nav-toggle')"): failures.append("console:focus-trap:return-focus")
    context.close()

    # Reuse the existing Data Workspace owner harness once; this includes sort/filter/unavailable/read-only state contracts.
    owner = smoke_ui.check_console(browser, root, {"width": 414, "height": 900})
    if owner.get("errors") or owner.get("horizontalOverflow") or owner.get("errorStates"):
        failures.append(f"console:data-workspace-owner:{owner}")


def audit_installer(browser, root: Path, failures: list[str]) -> None:
    document = smoke_ui.inline_document(root / "cmd/platform-installer/static", installer=True)
    for width in (280, 414):
        context = browser.new_context(viewport={"width": width, "height": 900})
        page = context.new_page()
        smoke_ui.prepare_page(page, document, installer=True)
        for route in INSTALLER_PAGES:
            page.evaluate("route => document.querySelector(`#nav [data-page='${route}']`).click()", route)
            page.wait_for_timeout(25)
            if page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 2"):
                failures.append(f"installer:{width}:ltr-overflow:{route}")
        page.evaluate("document.querySelector('#language-toggle').click()")
        for route in INSTALLER_PAGES:
            page.evaluate("route => document.querySelector(`#nav [data-page='${route}']`).click()", route)
            page.wait_for_timeout(25)
            if page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 2"):
                failures.append(f"installer:{width}:rtl-overflow:{route}")
        audit_dom(page, f"installer:{width}:rtl", failures)
        context.close()

    for theme in ("light", "dark"):
        context = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme=theme)
        page = context.new_page()
        smoke_ui.prepare_page(page, document, installer=True)
        audit_dom(page, f"installer:{theme}", failures)
        audit_contrast(page, f"installer:{theme}", failures)
        feedback = page.evaluate("""() => {
          const originalSetTimeout = window.setTimeout, delays=[];
          window.setTimeout=(fn, delay, ...args)=>{delays.push(delay);return 1;};
          try {
            toast('quality error','error');
            const error=document.querySelector('#toast-region .toast.error');
            const errorButton=error?.querySelector('button[aria-label=\"Close\"]');
            const errorRawGlyph=(errorButton?.textContent||'').trim();
            const errorHasIcon=!!errorButton?.querySelector('svg use[href=\"#icon-close\"]');
            const errorScheduled=delays.includes(5200);
            error?.remove();
            delays.length=0;
            toast('quality success','success');
            const success=document.querySelector('#toast-region .toast.success');
            const successScheduled=delays.includes(5200);
            success?.remove();
            return {errorRawGlyph,errorHasIcon,errorScheduled,successScheduled};
          } finally { window.setTimeout=originalSetTimeout; }
        }""")
        if feedback.get("errorRawGlyph") or not feedback.get("errorHasIcon"):
            failures.append(f"installer:{theme}:runtime-toast-action-icon:{feedback}")
        if feedback.get("errorScheduled") or not feedback.get("successScheduled"):
            failures.append(f"installer:{theme}:toast-durability:{feedback}")
        context.close()

    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page()
    smoke_ui.prepare_page(page, document, installer=True)
    page.locator("#menu-toggle").click()
    page.keyboard.press("Shift+Tab")
    if page.evaluate("document.activeElement?.dataset?.page") != "lifecycle": failures.append("installer:focus-trap:shift-tab")
    page.keyboard.press("Tab")
    if page.evaluate("document.activeElement?.dataset?.page") != "overview": failures.append("installer:focus-trap:tab-wrap")
    page.keyboard.press("Escape")
    if not page.evaluate("document.activeElement === document.querySelector('#menu-toggle')"): failures.append("installer:focus-trap:return-focus")
    context.close()


def main() -> int:
    root = ROOT
    failures = static_quality_failures(root)
    system_chromium = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    with sync_playwright() as playwright:
        chromium = system_chromium or playwright.chromium.executable_path
        if not chromium or not Path(chromium).is_file():
            raise SystemExit("UI_QUALITY_BROWSER_MISSING")
        browser = playwright.chromium.launch(headless=True, executable_path=chromium, args=["--no-sandbox"])
        audit_console(browser, root, failures)
        audit_installer(browser, root, failures)
        browser.close()
    result = {"schemaVersion": 1, "status": "PASS" if not failures else "FAIL", "failures": failures}
    output = evidence_dir() / "product-console-quality-gates.json"
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("UI_QUALITY_GATES_" + result["status"], output)
    if failures:
        for failure in failures:
            print(" -", failure)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
