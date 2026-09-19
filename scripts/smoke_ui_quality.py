#!/usr/bin/env python3
"""Rendered UI quality gates for the Operator Console and Bootstrap Installer.

This is a stable owner-level verification suite. It adapts useful verification
ideas from public UX/UI agent guidance without importing a foreign design
system, runtime dependency, or agent harness.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tempfile


ROOT = Path(__file__).resolve().parent.parent
SMOKE_SPEC = importlib.util.spec_from_file_location("platform_factory_smoke_ui", ROOT / "scripts" / "smoke_ui.py")
if SMOKE_SPEC is None or SMOKE_SPEC.loader is None:
    raise RuntimeError("unable to load smoke_ui owner helpers")
smoke_ui = importlib.util.module_from_spec(SMOKE_SPEC)
SMOKE_SPEC.loader.exec_module(smoke_ui)

CONSOLE_PAGES = [
    "overview", "workspace", "installation", "clusters", "providers", "blueprints", "templates", "marketplace", "baselines",
    "verification", "fleet", "workspaces", "tenants", "operations", "notifications", "services", "catalog", "validator",
]
INSTALLER_PAGES = ["overview", "installation", "progress", "health", "recovery", "lifecycle"]


def parse_shard(value: str) -> tuple[int, int]:
    raw = str(value or "").strip()
    if not raw:
        return (0, 1)
    try:
        index_text, count_text = raw.split("/", 1)
        index, count = int(index_text), int(count_text)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("shard must be INDEX/COUNT") from exc
    if count < 1 or index < 0 or index >= count:
        raise argparse.ArgumentTypeError("shard requires COUNT>=1 and 0<=INDEX<COUNT")
    return index, count


def select_shard(routes: list[str], shard: tuple[int, int]) -> list[str]:
    index, count = shard
    return [route for position, route in enumerate(routes) if position % count == index]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scope", choices=("all", "console", "installer"), default="all",
        help="limit this checkpoint to one UI surface; default keeps the historical full gate",
    )
    parser.add_argument(
        "--shard", type=parse_shard, default=(0, 1), metavar="INDEX/COUNT",
        help="checkpoint-safe route shard; default 0/1 preserves full route coverage",
    )
    auxiliary = parser.add_mutually_exclusive_group()
    auxiliary.add_argument(
        "--skip-auxiliary", action="store_true",
        help="run only the selected route matrix; use with a separate --auxiliary-only checkpoint",
    )
    auxiliary.add_argument(
        "--auxiliary-only", action="store_true",
        help="run only non-route focus/theme/motion/feedback checks for the selected scope",
    )
    return parser.parse_args(argv)


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


def load_console_resource_scope_registry(root: Path = ROOT) -> dict[str, object]:
    registry = json.loads((root / "internal/api/resource_scope_registry.json").read_text(encoding="utf-8"))
    families = registry.get("families")
    if registry.get("authority") != "RESOURCE_SCOPE_REGISTRY_V1" or not isinstance(families, list):
        raise RuntimeError("UI_QUALITY_RESOURCE_SCOPE_REGISTRY_INVALID")
    if registry.get("classifiedCount") != len(families):
        raise RuntimeError("UI_QUALITY_RESOURCE_SCOPE_REGISTRY_INCOMPLETE")
    return registry


def prepare_quality_page(page, document: str, *, installer: bool, root: Path = ROOT) -> None:
    if installer:
        smoke_ui.prepare_page(page, document, installer=True)
        return
    smoke_ui.prepare_page(
        page, document, installer=False, resource_scope_registry=load_console_resource_scope_registry(root)
    )


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
    let target = el;
    if (el.tagName === 'INPUT' && ['checkbox','radio'].includes(String(el.type).toLowerCase())) {
      const label = el.closest('label');
      if (label && visible(label)) target = label;
    }
    const r = target.getBoundingClientRect();
    return r.width < 24 || r.height < 24;
  }).map(el => {
    let target = el;
    if (el.tagName === 'INPUT' && ['checkbox','radio'].includes(String(el.type).toLowerCase())) target = el.closest('label') || el;
    const r=target.getBoundingClientRect();
    return {tag:el.tagName,id:el.id,width:Math.round(r.width),height:Math.round(r.height)};
  });
  return {duplicateIds, unnamedActions, unlabeledFields, unnamedDialogs, undersizedTargets};
}"""

CONTRAST_AUDIT_JS = r"""() => {
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
  function visible(el) {
    const s=getComputedStyle(el), r=el.getBoundingClientRect();
    return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0 && !el.disabled;
  }
  function ratio(el) {
    let layers=[], current=el;
    while (current) { layers.push(rgba(getComputedStyle(current).backgroundColor)); current=current.parentElement; }
    let background=[255,255,255,1];
    for (let index=layers.length-1; index>=0; index--) background=composite(layers[index], background);
    const foreground=rgba(getComputedStyle(el).color), a=luminance(foreground), b=luminance(background);
    return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);
  }
  const selectors=['#primary-nav button.active','#section-nav button.active','button.primary','button.secondary','button.danger','button.link-button','summary','.badge'];
  const failures=[];
  for (const selector of selectors) {
    let seen=0;
    for (const el of document.querySelectorAll(selector)) {
      if (!visible(el)) continue;
      if (seen++ >= 6) break;
      const value=ratio(el);
      if (value < 4.5) failures.push({selector,ratio:value,text:String(el.innerText || el.getAttribute('aria-label') || selector).trim().slice(0,50)});
    }
  }
  return failures;
}"""


def audit_dom(page, label: str, failures: list[str]) -> None:
    result = page.evaluate(DOM_AUDIT_JS)
    for key, values in result.items():
        if values:
            failures.append(f"{label}:{key}:{values[:5]}")


def audit_contrast(page, label: str, failures: list[str]) -> None:
    for item in page.evaluate(CONTRAST_AUDIT_JS):
        failures.append(f"{label}:contrast:{item['selector']}:{float(item['ratio']):.2f}:{item['text']}")


def _set_direction(page, direction: str) -> None:
    current = page.evaluate("document.documentElement.dir || 'ltr'")
    if current != direction:
        page.evaluate("document.querySelector(\"#language-toggle\").click()")
        page.wait_for_timeout(1)
    observed = page.evaluate("document.documentElement.dir || 'ltr'")
    if observed != direction:
        raise AssertionError(f"direction switch failed: expected={direction} observed={observed}")


def _audit_route_matrix(browser, document: str, *, installer: bool, routes: list[str], failures: list[str], root: Path = ROOT) -> dict[str, int]:
    widths = (320, 390, 768, 1024, 1440)
    themes = ("light", "dark")
    directions = ("ltr", "rtl")
    accessibility_states = 0
    contrast_states = 0
    app = "installer" if installer else "console"
    for width in widths:
        height = 844 if width == 390 else 900
        context = browser.new_context(viewport={"width": width, "height": height})
        page = context.new_page()
        prepare_quality_page(page, document, installer=installer, root=root)
        page.add_style_tag(content="*,*::before,*::after{transition:none!important;animation:none!important}")

        # DOM semantics, target sizing and overflow do not change with theme.
        # Exercise every route at every supported viewport in both LTR and RTL.
        page.emulate_media(color_scheme="light")
        if not installer:
            page.evaluate("theme => applyConsoleTheme(theme)", "light")
        for direction in directions:
            _set_direction(page, direction)
            for route in routes:
                if installer:
                    page.evaluate("route => document.querySelector(`#nav [data-page='${route}']`).click()", route)
                else:
                    page.evaluate("route => navigate(route)", route)
                label = f"{app}:{width}:accessibility:{direction}:{route}"
                if page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 2"):
                    failures.append(f"{label}:horizontal-overflow")
                audit_dom(page, label, failures)
                accessibility_states += 1

        # Contrast is direction-independent, but it can vary by viewport, route
        # visibility and explicit/system theme. Exercise every route at every
        # supported viewport in both light and dark.
        _set_direction(page, "ltr")
        for theme in themes:
            page.emulate_media(color_scheme=theme)
            if not installer:
                page.evaluate("theme => applyConsoleTheme(theme)", theme)
            for route in routes:
                if installer:
                    page.evaluate("route => document.querySelector(`#nav [data-page='${route}']`).click()", route)
                else:
                    page.evaluate("route => navigate(route)", route)
                audit_contrast(page, f"{app}:{width}:contrast:{theme}:{route}", failures)
                contrast_states += 1
        context.close()
    return {
        "widths": len(widths), "themes": len(themes), "directions": len(directions), "routes": len(routes),
        "accessibilityRouteStates": accessibility_states, "contrastRouteStates": contrast_states,
    }

def audit_console(browser, root: Path, failures: list[str], *, routes: list[str] | None = None, run_auxiliary: bool = True, run_matrix: bool = True) -> dict[str, int]:
    document = smoke_ui.inline_document(root / "webconsole/static")
    selected = list(CONSOLE_PAGES if routes is None else routes)
    coverage = _audit_route_matrix(browser, document, installer=False, routes=selected, failures=failures, root=root) if run_matrix else {
        "widths": 0, "themes": 0, "directions": 0, "routes": 0, "accessibilityRouteStates": 0, "contrastRouteStates": 0
    }
    if not run_auxiliary:
        return coverage

    # Explicit focus visibility and durable feedback contracts in both themes.
    for theme in ("light", "dark"):
        context = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme=theme)
        page = context.new_page()
        prepare_quality_page(page, document, installer=False, root=root)
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
            error?.remove(); delays.length=0;
            toast('quality success','success');
            const success=document.querySelector('#toast-region .toast.success');
            const successScheduled=delays.includes(5200); success?.remove();
            return {errorRawGlyph,errorHasIcon,errorScheduled,successScheduled};
          } finally { window.setTimeout=originalSetTimeout; }
        }""")
        if feedback.get("errorRawGlyph") or not feedback.get("errorHasIcon"):
            failures.append(f"console:{theme}:runtime-toast-action-icon:{feedback}")
        if feedback.get("errorScheduled") or not feedback.get("successScheduled"):
            failures.append(f"console:{theme}:toast-durability:{feedback}")
        context.close()

    # Explicit console theme preference must override the opposite OS preference.
    # This prevents system-dark selectors from contaminating an explicit light
    # preference (and vice versa).
    for system_theme, explicit_theme in (("dark", "light"), ("light", "dark")):
        context = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme=system_theme)
        page = context.new_page(); prepare_quality_page(page, document, installer=False, root=root)
        page.add_style_tag(content="*,*::before,*::after{transition:none!important;animation:none!important}")
        page.evaluate("theme => applyConsoleTheme(theme)", explicit_theme)
        observed = page.evaluate("""() => ({
          theme: document.documentElement.dataset.theme,
          body: getComputedStyle(document.body).backgroundColor,
          secondaryColor: getComputedStyle(document.querySelector('button.secondary')).color,
          secondaryBackground: getComputedStyle(document.querySelector('button.secondary')).backgroundColor
        })""")
        if observed.get("theme") != explicit_theme:
            failures.append(f"console:theme-override:{system_theme}->{explicit_theme}:attribute:{observed}")
        audit_contrast(page, f"console:theme-override:{system_theme}->{explicit_theme}", failures)
        context.close()

    # Keyboard mobile-navigation trap and return-focus contract.
    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page(); prepare_quality_page(page, document, installer=False, root=root)
    page.locator("#mobile-nav-toggle").click(); page.keyboard.press("Shift+Tab")
    if page.evaluate("document.activeElement?.id") != "logout": failures.append("console:focus-trap:shift-tab")
    page.keyboard.press("Tab")
    if page.evaluate("document.activeElement?.dataset?.section") != "home": failures.append("console:focus-trap:tab-wrap")
    page.keyboard.press("Escape")
    if not page.evaluate("document.activeElement === document.querySelector('#mobile-nav-toggle')"): failures.append("console:focus-trap:return-focus")
    context.close()

    # Reduced-motion must suppress animated transitions rather than merely changing color.
    context = browser.new_context(viewport={"width": 1440, "height": 900}, reduced_motion="reduce")
    page = context.new_page(); prepare_quality_page(page, document, installer=False, root=root)
    motion = page.evaluate("""() => {
      const probe=document.querySelector('.page.active') || document.body;
      const s=getComputedStyle(probe);
      return {animationDuration:s.animationDuration,transitionDuration:s.transitionDuration};
    }""")
    def duration_seconds(value: str) -> float:
        value = value.strip()
        if value.endswith("ms"):
            return float(value[:-2]) / 1000.0
        if value.endswith("s"):
            return float(value[:-1])
        return 999.0
    if duration_seconds(motion["animationDuration"]) > 0.00001 or duration_seconds(motion["transitionDuration"]) > 0.00001:
        failures.append(f"console:reduced-motion-not-respected:{motion}")
    context.close()

    owner = smoke_ui.check_console(browser, root, {"width": 414, "height": 900})
    if owner.get("errors") or owner.get("horizontalOverflow") or owner.get("errorStates"):
        failures.append(f"console:data-workspace-owner:{owner}")
    return coverage


def audit_installer(browser, root: Path, failures: list[str], *, routes: list[str] | None = None, run_auxiliary: bool = True, run_matrix: bool = True) -> dict[str, int]:
    document = smoke_ui.inline_document(root / "cmd/platform-installer/static", installer=True)
    selected = list(INSTALLER_PAGES if routes is None else routes)
    coverage = _audit_route_matrix(browser, document, installer=True, routes=selected, failures=failures, root=root) if run_matrix else {
        "widths": 0, "themes": 0, "directions": 0, "routes": 0, "accessibilityRouteStates": 0, "contrastRouteStates": 0
    }
    if not run_auxiliary:
        return coverage

    for theme in ("light", "dark"):
        context = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme=theme)
        page = context.new_page(); prepare_quality_page(page, document, installer=True, root=root)
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
            error?.remove(); delays.length=0;
            toast('quality success','success');
            const success=document.querySelector('#toast-region .toast.success');
            const successScheduled=delays.includes(5200); success?.remove();
            return {errorRawGlyph,errorHasIcon,errorScheduled,successScheduled};
          } finally { window.setTimeout=originalSetTimeout; }
        }""")
        if feedback.get("errorRawGlyph") or not feedback.get("errorHasIcon"):
            failures.append(f"installer:{theme}:runtime-toast-action-icon:{feedback}")
        if feedback.get("errorScheduled") or not feedback.get("successScheduled"):
            failures.append(f"installer:{theme}:toast-durability:{feedback}")
        context.close()

    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page(); prepare_quality_page(page, document, installer=True, root=root)
    page.locator("#menu-toggle").click(); page.keyboard.press("Shift+Tab")
    if page.evaluate("document.activeElement?.dataset?.page") != "lifecycle": failures.append("installer:focus-trap:shift-tab")
    page.keyboard.press("Tab")
    if page.evaluate("document.activeElement?.dataset?.page") != "overview": failures.append("installer:focus-trap:tab-wrap")
    page.keyboard.press("Escape")
    if not page.evaluate("document.activeElement === document.querySelector('#menu-toggle')"): failures.append("installer:focus-trap:return-focus")
    context.close()
    return coverage

def main(argv: list[str] | None = None) -> int:
    from playwright.sync_api import sync_playwright
    args = parse_args(argv)
    root = ROOT
    failures = static_quality_failures(root)
    shard_index, shard_count = args.shard
    run_matrix = not args.auxiliary_only
    run_auxiliary = args.auxiliary_only or (not args.skip_auxiliary and shard_index == 0)
    console_routes = select_shard(CONSOLE_PAGES, args.shard) if args.scope in {"all", "console"} and run_matrix else []
    installer_routes = select_shard(INSTALLER_PAGES, args.shard) if args.scope in {"all", "installer"} and run_matrix else []
    if run_matrix and args.scope in {"all", "console"} and not console_routes:
        failures.append(f"console:empty-shard:{shard_index}/{shard_count}")
    if run_matrix and args.scope in {"all", "installer"} and not installer_routes:
        failures.append(f"installer:empty-shard:{shard_index}/{shard_count}")

    system_chromium = os.environ.get("PLATFORM_FACTORY_UI_BROWSER_EXECUTABLE", "").strip() or shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    coverage: dict[str, dict[str, int]] = {}
    with sync_playwright() as playwright:
        chromium = system_chromium or playwright.chromium.executable_path
        if not chromium or not Path(chromium).is_file():
            raise SystemExit("UI_QUALITY_BROWSER_MISSING")
        browser = playwright.chromium.launch(headless=True, executable_path=chromium, args=["--no-sandbox"])
        if args.scope in {"all", "console"}:
            coverage["console"] = audit_console(
                browser, root, failures, routes=console_routes, run_auxiliary=run_auxiliary, run_matrix=run_matrix
            )
        if args.scope in {"all", "installer"}:
            coverage["installer"] = audit_installer(
                browser, root, failures, routes=installer_routes, run_auxiliary=run_auxiliary, run_matrix=run_matrix
            )
        browser.close()

    result = {
        "schemaVersion": 3,
        "authority": "OPERATOR_EXPERIENCE_VIEWPORT_ACCESSIBILITY_V1",
        "status": "PASS" if not failures else "FAIL",
        "checkpoint": {
            "scope": args.scope,
            "shardIndex": shard_index,
            "shardCount": shard_count,
            "routeMatrix": run_matrix,
            "auxiliaryChecks": run_auxiliary,
            "consoleRoutes": console_routes,
            "installerRoutes": installer_routes,
        },
        "coverage": coverage,
        "failures": failures,
    }
    if args.scope == "all" and args.shard == (0, 1) and not args.skip_auxiliary and not args.auxiliary_only:
        suffix = ""
    elif args.auxiliary_only:
        suffix = f"-{args.scope}-auxiliary"
    else:
        suffix = f"-{args.scope}-{shard_index}-of-{shard_count}"
    output = evidence_dir() / f"product-console-quality-gates{suffix}.json"
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("UI_QUALITY_GATES_" + result["status"], output)
    if failures:
        for failure in failures:
            print(" -", failure)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
