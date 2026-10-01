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
    "overview", "workspace", "installation", "clusters", "providers", "blueprints", "templates", "applications", "dapr", "marketplace", "baselines",
    "verification", "edge", "fleet", "workspaces", "finops", "tenants", "operations", "ai", "notifications", "services",
    "catalog", "lab", "validator",
]
TASK_FIRST_DISCLOSURE_ROUTES = {
    "workspace", "clusters", "providers", "templates", "applications", "baselines",
    "verification", "edge", "workspaces", "finops", "tenants", "operations", "catalog",
}
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
    route_contracts = (
        ("webconsole/static/index.html", CONSOLE_PAGES),
        ("cmd/platform-installer/static/index.html", INSTALLER_PAGES),
    )
    for rel, expected_routes in route_contracts:
        html = (root / rel).read_text(encoding="utf-8")
        if rel == "webconsole/static/index.html":
            app_start = html.find('id="applications"')
            dapr_start = html.find('id="dapr"')
            blueprint_start = html.find('id="blueprints"')
            if min(app_start, dapr_start, blueprint_start) < 0 or not (app_start < dapr_start < blueprint_start):
                failures.append(f"{rel}:application-dapr-route-order-drift")
            else:
                application_slice = html[app_start:dapr_start]
                dapr_slice = html[dapr_start:blueprint_start]
                if 'id="dapr-runtime-workflow"' in application_slice:
                    failures.append(f"{rel}:dapr-workflow-leaked-into-application-delivery")
                if 'data-viewer-safe="true" id="dapr-assessment-form"' not in dapr_slice or 'data-viewer-safe="true" id="dapr-workload-form"' not in dapr_slice:
                    failures.append(f"{rel}:dapr-readonly-workflows-not-viewer-safe")
        rendered_routes = []
        for tag in re.findall(r"<section\\b[^>]*>", html, flags=re.I):
            class_match = re.search(r'\\bclass="([^"]*)"', tag, flags=re.I)
            id_match = re.search(r'\\bid="([^"]+)"', tag, flags=re.I)
            classes = set((class_match.group(1) if class_match else "").split())
            if "page" in classes and id_match:
                rendered_routes.append(id_match.group(1))
        if len(rendered_routes) != len(set(rendered_routes)):
            failures.append(f"{rel}:duplicate-page-route:{rendered_routes}")
        missing = sorted(set(rendered_routes) - set(expected_routes))
        stale = sorted(set(expected_routes) - set(rendered_routes))
        if missing or stale:
            failures.append(f"{rel}:route-matrix-drift:missing-from-matrix={missing}:stale-in-matrix={stale}")
    console_html = (root / "webconsole/static/index.html").read_text(encoding="utf-8")
    contextual_routes = re.findall(r'<button\b[^>]*\bdata-page="([^"]+)"[^>]*>', console_html, flags=re.I)
    contextual_expected = [route for route in CONSOLE_PAGES if route != "overview"]
    duplicate_contextual = sorted({route for route in contextual_routes if contextual_routes.count(route) > 1})
    missing_contextual = sorted(set(contextual_expected) - set(contextual_routes))
    stale_contextual = sorted(set(contextual_routes) - set(contextual_expected))
    if duplicate_contextual or missing_contextual or stale_contextual:
        failures.append(
            "webconsole/static/index.html:contextual-navigation-parity:"
            f"duplicate={duplicate_contextual}:missing={missing_contextual}:stale={stale_contextual}"
        )
    primary_sections = re.findall(r'<button\b[^>]*\bdata-section="([^"]+)"[^>]*\bdata-section-home="([^"]+)"[^>]*>', console_html, flags=re.I)
    if len(primary_sections) != 7 or len({section for section, _ in primary_sections}) != 7:
        failures.append(f"webconsole/static/index.html:primary-navigation-domain-count:{primary_sections}")
    for section, home in primary_sections:
        if home not in CONSOLE_PAGES:
            failures.append(f"webconsole/static/index.html:primary-navigation-home-missing:{section}:{home}")

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

    console_css = (root / "webconsole/static/styles.css").read_text(encoding="utf-8")
    installer_css = (root / "cmd/platform-installer/static/styles.css").read_text(encoding="utf-8")
    console_js = (root / "webconsole/static/app.js").read_text(encoding="utf-8")
    v4_css_contracts = (
        "Operator Horizon V4 — Persian-native technical shell",
        "--ui-background:var(--bg)",
        "--ui-radius-control:8px",
        "--ui-motion:180ms",
        'html[lang="fa"] body{font-size:15px;line-height:1.75;letter-spacing:0}',
        'html[lang="fa"] :where(h1,h2,h3,h4,.eyebrow,.nav-group>span,.page-outcome-label,.workflow-eyebrow,.product-flow strong)',
        "letter-spacing:0;text-transform:none",
        "padding-inline-start:8px;padding-inline-end:28px",
        'html[dir="rtl"] :where(.technical,code,pre,kbd,[data-ltr="true"],input[type="email"],input[type="url"],input[type="tel"])',
        "font-variant-numeric:tabular-nums",
    )
    for contract in v4_css_contracts:
        if contract not in console_css:
            failures.append(f"webconsole/static/styles.css:persian-native-contract:{contract}")
    v4_js_contracts = (
        "const displayNumber=value=>",
        "fa-IR-u-nu-arabext",
        "fa-IR-u-ca-persian-nu-arabext",
        "count.textContent=displayNumber(records.length)",
        "displayNumber(Math.max(0,managed-connected))",
    )
    for contract in v4_js_contracts:
        if contract not in console_js:
            failures.append(f"webconsole/static/app.js:persian-native-contract:{contract}")
    single_selector_collection = re.compile(r'(?<!\$)\$\([^\)\n]*\)\.(?:map|filter|forEach)\b')
    for match in single_selector_collection.finditer(console_js):
        failures.append(f"webconsole/static/app.js:single-selector-used-as-collection:{match.group(0)}")
    physical_layout = re.compile(r"\b(?:margin|padding|border)-(?:left|right)\b|(?:^|[;{])\s*(?:left|right)\s*:", re.M)
    for rel, css in (
        ("webconsole/static/styles.css", console_css),
        ("cmd/platform-installer/static/styles.css", installer_css),
    ):
        if "flex-direction:row-reverse" in css.replace(" ", ""):
            failures.append(f"{rel}:rtl-physical-reversal-forbidden")
        for match in physical_layout.finditer(css):
            failures.append(f"{rel}:rtl-physical-layout-property:{match.group(0).strip()}")
        for rule in re.finditer(r"([^{}]+)\{([^{}]*)\}", css, flags=re.S):
            selector, body = rule.group(1).lower(), rule.group(2).lower()
            if "rtl" in selector and re.search(r"text-align\s*:\s*(?:left|right)\b", body):
                failures.append(f"{rel}:rtl-physical-text-align:{rule.group(1).strip()}")
    if "Create WorkloadType authority through Product API or MCP" in console_js:
        failures.append("webconsole/static/app.js:application-composition-api-only-empty-state")
    for marker in ("emptyDisclosureState", "emptyFocusState", "application-composition-library", "application-binding-workflow", "renderDaprRuntimePrerequisite", "assessAndResumeDaprRuntime", "latestOperation"):
        if marker not in console_js:
            failures.append(f"webconsole/static/app.js:actionable-empty-state-direct-action-missing:{marker}")
    actionable_empty_state_owners = {
        "assurance-start-workflow": "runtime-certification-project",
        "fleet-slo-workflow": "reliability-slo-cluster",
        "fleet-recovery-workflow": "recovery-cluster",
        "data-protection-console": "data-protection-cluster",
        "fleet-configuration-workflow": "fleet-project",
        "template-schema-workflow": "template-schema-project",
        "template-policy-workflow": "template-policy-project",
        "platform-template-workflow": "platform-template-project",
        "finops-budget-workflow": "finops-budget-organization",
        "finops-rate-card-workflow": "finops-rate-card-organization",
        "membership-workflow": "membership-organization",
        "oidc-mapping-workflow": "oidc-group-name",
        "service-account-workflow": "service-account-organization",
        "cluster-import-console": "cluster-project",
    }
    for disclosure, focus_target in actionable_empty_state_owners.items():
        if f'id="{disclosure}"' not in console_html:
            failures.append(f"webconsole/static/index.html:actionable-empty-state-owner-missing:{disclosure}")
        if f"'{disclosure}'" not in console_js or f"'{focus_target}'" not in console_js:
            failures.append(f"webconsole/static/app.js:actionable-empty-state-direct-action-missing:{disclosure}:{focus_target}")
    for focus_target in ("maintenance-window-name", "blueprint-project", "global-organization-scope"):
        if f'id="{focus_target}"' not in console_html:
            failures.append(f"webconsole/static/index.html:focus-empty-state-owner-missing:{focus_target}")
        if f"'{focus_target}'" not in console_js:
            failures.append(f"webconsole/static/app.js:focus-empty-state-direct-action-missing:{focus_target}")
    for marker in ("id=\"dapr-prerequisite\"", "data-dapr-prerequisite-kind", "application-runtime.dapr"):
        haystack = console_html if marker.startswith("id=") else console_js
        if marker not in haystack:
            failures.append(f"webconsole:dapr-actionable-prerequisite-missing:{marker}")
    for phrase in (">Left release<", ">Right release<", "stays above", "form above", "connect Forgejo below"):
        if phrase.lower() in console_html.lower() or phrase.lower() in console_js.lower():
            failures.append(f"webconsole:physical-position-copy:{phrase}")
    for phrase in ("Use Ctrl/Command to select multiple", "Ctrl/Command to select multiple", "click the button", "tap the button", "hover over"):
        if phrase.lower() in console_html.lower() or phrase.lower() in console_js.lower():
            failures.append(f"webconsole:input-method-specific-guidance:{phrase}")
    if re.search(r"behavior\s*:\s*['\"]smooth['\"]", console_js):
        failures.append("webconsole/static/app.js:programmatic-scroll-bypasses-reduced-motion")
    if "const motionSafeBehavior=()=>motionSafeBehavior()" in console_js:
        failures.append("webconsole/static/app.js:reduced-motion-helper-self-recursion")
    if "const motionSafeBehavior=()=>window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth';" not in console_js:
        failures.append("webconsole/static/app.js:reduced-motion-helper-missing")
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
  const bidiDirectionErrors = document.documentElement.dir === 'rtl'
    ? [...document.querySelectorAll('.technical,code,pre,kbd,[data-ltr="true"],input[type="email"],input[type="url"],input[type="tel"],[dir="ltr"]')]
        .filter(visible)
        .filter(el => getComputedStyle(el).direction !== 'ltr')
        .map(el => ({tag:el.tagName,id:el.id || '',direction:getComputedStyle(el).direction,text:String(el.textContent || el.value || '').trim().slice(0,80)}))
    : [];
  const rtlForwardArrowErrors = document.documentElement.dir === 'rtl'
    ? [...document.querySelectorAll('.page.active *')]
        .filter(visible)
        .filter(el => el.children.length === 0 && !el.closest('.technical,code,pre,kbd,[data-ltr="true"],[data-no-translate]'))
        .filter(el => String(el.textContent || '').includes('→'))
        .map(el => ({tag:el.tagName,id:el.id || '',text:String(el.textContent || '').trim().slice(0,120)}))
    : [];
  return {duplicateIds, unnamedActions, unlabeledFields, unnamedDialogs, undersizedTargets, bidiDirectionErrors, rtlForwardArrowErrors};
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
    expanded_accessibility_states = 0
    application_task_accessibility_states = 0
    contrast_states = 0
    application_task_contrast_states = 0
    app = "installer" if installer else "console"
    for width in widths:
        height = 844 if width == 390 else 900
        context = browser.new_context(viewport={"width": width, "height": height})
        page = context.new_page()
        prepare_quality_page(page, document, installer=installer, root=root)
        page.add_style_tag(content="*,*::before,*::after{transition:none!important;animation:none!important}")

        # DOM semantics, target sizing, bidi isolation and overflow must hold in
        # both the normal progressive-disclosure state and with every workflow
        # disclosure expanded. This keeps hidden form stages from escaping the
        # E2E RTL/LTR gate.
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
                if not installer:
                    navigation = page.evaluate("""route => {
                      const primary=[...document.querySelectorAll('#primary-nav button.active')];
                      const secondary=[...document.querySelectorAll('#section-nav button.active')];
                      const sectionNav=document.querySelector('#section-nav');
                      const activeSecondary=secondary[0] || null;
                      const navRect=sectionNav && !sectionNav.hidden ? sectionNav.getBoundingClientRect() : null;
                      const activeRect=activeSecondary ? activeSecondary.getBoundingClientRect() : null;
                      return {
                        primaryCount: primary.length,
                        secondaryCount: secondary.length,
                        primaryCurrent: primary.map(node=>node.getAttribute('aria-current')),
                        secondaryCurrent: secondary.map(node=>node.getAttribute('aria-current')),
                        activeSecondaryPage: activeSecondary?.dataset?.page || '',
                        sectionHidden: Boolean(sectionNav?.hidden),
                        activeSecondaryVisible: !activeRect || !navRect || (
                          activeRect.left >= navRect.left - 2 && activeRect.right <= navRect.right + 2
                        ),
                        heading:String((document.querySelector('.page.active .section-intro h2, .page.active .page-heading h1, .page.active .operator-briefing h1, .page.active .operator-briefing h2')?.textContent)||'').trim(),
                        outcomeCount:document.querySelectorAll('.page.active .page-outcome-strip').length,
                        outcomeText:String(document.querySelector('.page.active .page-outcome-strip')?.textContent||'').replace(/\s+/g,' ').trim(),
                        surfaceCount:document.querySelectorAll('.page.active .panel, .page.active .action-console, .page.active .metric-grid, .page.active .operator-briefing, .page.active .product-flow, .page.active .data-table-shell').length
                      };
                    }""", route)
                    expected_secondary = route != "overview"
                    if navigation.get("primaryCount") != 1:
                        failures.append(f"{label}:primary-nav-active-count:{navigation}")
                    if expected_secondary:
                        if navigation.get("secondaryCount") != 1 or navigation.get("activeSecondaryPage") != route or navigation.get("sectionHidden") or not navigation.get("activeSecondaryVisible") or navigation.get("secondaryCurrent") != ["page"]:
                            failures.append(f"{label}:secondary-nav-route-state:{navigation}")
                    elif navigation.get("secondaryCount") != 0 or not navigation.get("sectionHidden"):
                        failures.append(f"{label}:overview-secondary-nav-state:{navigation}")
                    if not navigation.get("heading") or navigation.get("outcomeCount") != 1 or not navigation.get("outcomeText") or navigation.get("surfaceCount",0) < 1:
                        failures.append(f"{label}:route-journey-framing:{navigation}")
                if not installer and route in TASK_FIRST_DISCLOSURE_ROUTES:
                    undisclosed = page.evaluate("""() => {
                      const active=document.querySelector('.page.active');
                      if(!active)return [];
                      return [...active.querySelectorAll('form')]
                        .filter(form => !form.closest('details'))
                        .map(form => form.id || form.getAttribute('action') || 'anonymous-form');
                    }""")
                    if undisclosed:
                        failures.append(f"{label}:task-first-undisclosed-forms:{undisclosed[:5]}")
                audit_dom(page, label, failures)
                accessibility_states += 1

                open_states = page.evaluate("""() => {
                  const active=document.querySelector('.page.active') || document.body;
                  const details=[...active.querySelectorAll('details')];
                  const states=details.map(item=>item.open);
                  details.forEach(item=>{item.open=true;});
                  return states;
                }""")
                expanded_label = f"{label}:expanded"
                if page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 2"):
                    failures.append(f"{expanded_label}:horizontal-overflow")
                audit_dom(page, expanded_label, failures)
                expanded_accessibility_states += 1
                if not installer and route == "applications":
                    for task in ("workload", "profile", "trait", "resource"):
                        task_label = f"{expanded_label}:composition:{task}"
                        page.evaluate("""task => {
                          const library=document.querySelector('#application-composition-library');
                          if(library?.matches('details'))library.open=true;
                          selectApplicationLibraryTask(task);
                        }""", task)
                        if page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 2"):
                            failures.append(f"{task_label}:horizontal-overflow")
                        audit_dom(page, task_label, failures)
                        application_task_accessibility_states += 1
                    page.evaluate("() => selectApplicationLibraryTask('workload')")
                page.evaluate("""states => {
                  const active=document.querySelector('.page.active') || document.body;
                  [...active.querySelectorAll('details')].forEach((item,index)=>{item.open=Boolean(states[index]);});
                }""", open_states)

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
                if not installer and route == "applications":
                    page.evaluate("""() => {
                      const library=document.querySelector('#application-composition-library');
                      if(library?.matches('details'))library.open=true;
                    }""")
                    for task in ("workload", "profile", "trait", "resource"):
                        page.evaluate("task => selectApplicationLibraryTask(task)", task)
                        audit_contrast(page, f"{app}:{width}:contrast:{theme}:{route}:composition:{task}", failures)
                        application_task_contrast_states += 1
                    page.evaluate("() => selectApplicationLibraryTask('workload')")
        context.close()
    return {
        "widths": len(widths), "themes": len(themes), "directions": len(directions), "routes": len(routes),
        "accessibilityRouteStates": accessibility_states,
        "expandedAccessibilityRouteStates": expanded_accessibility_states,
        "applicationCompositionTaskAccessibilityStates": application_task_accessibility_states,
        "contrastRouteStates": contrast_states,
        "applicationCompositionTaskContrastStates": application_task_contrast_states,
    }

def audit_console(browser, root: Path, failures: list[str], *, routes: list[str] | None = None, run_auxiliary: bool = True, run_matrix: bool = True) -> dict[str, int]:
    document = smoke_ui.inline_document(root / "webconsole/static")
    selected = list(CONSOLE_PAGES if routes is None else routes)
    coverage = _audit_route_matrix(browser, document, installer=False, routes=selected, failures=failures, root=root) if run_matrix else {
        "widths": 0, "themes": 0, "directions": 0, "routes": 0, "accessibilityRouteStates": 0,
        "expandedAccessibilityRouteStates": 0, "applicationCompositionTaskAccessibilityStates": 0,
        "contrastRouteStates": 0, "applicationCompositionTaskContrastStates": 0
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

    # Persistent validation must survive RTL/LTR direction changes and expose
    # field-level + form-level accessible feedback rather than native bubbles only.
    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page(); prepare_quality_page(page, document, installer=False, root=root)
    validation = page.evaluate("""() => {
      document.querySelectorAll('.page').forEach(node=>node.classList.toggle('active',node.id==='applications'));
      const library=document.querySelector('#application-composition-library'); if(library)library.open=true;
      if(document.documentElement.dir!=='ltr')document.querySelector('#language-toggle')?.click();
      const form=document.querySelector('#application-workload-create-form');
      const field=document.querySelector('#application-workload-name');
      form?.reportValidity();
      const before=field?.id ? document.querySelector('#'+CSS.escape(field.id)+'-error')?.textContent || '' : '';
      const described=String(field?.getAttribute('aria-describedby')||'');
      const summary=String(form?.querySelector('.form-validation-summary')?.textContent||'');
      document.querySelector('#language-toggle')?.click();
      const after=field?.id ? document.querySelector('#'+CSS.escape(field.id)+'-error')?.textContent || '' : '';
      return {invalid:field?.getAttribute('aria-invalid'),before,after,described,summary,dir:document.documentElement.dir};
    }""")
    if validation.get("invalid") != "true" or not validation.get("before") or not validation.get("after") or validation.get("before") == validation.get("after") or not validation.get("described") or not validation.get("summary") or validation.get("dir") != "rtl":
        failures.append(f"console:persistent-localized-validation:{validation}")
    context.close()

    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page(); prepare_quality_page(page, document, installer=False, root=root)
    availability = page.evaluate("""() => {
      const active=document.querySelector('.page.active');
      const probe=document.createElement('button');
      probe.type='button';probe.disabled=true;probe.dataset.accessDisabled='true';probe.dataset.accessReason='Read-only session';
      probe.hidden=true;active.append(probe);
      const read=()=>({
        dir:document.documentElement.dir,
        text:String(document.querySelector('#page-action-availability')?.textContent||'').replace(/\s+/g,' ').trim()
      });
      state.locale='en';applyLocale();const en=read();
      state.locale='fa';applyLocale();const fa=read();
      state.locale='en';applyLocale();const enAgain=read();
      probe.remove();renderActionAvailability();
      return {en,fa,enAgain};
    }""")
    if availability.get("en",{}).get("dir") != "ltr" or "Some actions are unavailable in the current context" not in availability.get("en",{}).get("text","") or "Read-only session" not in availability.get("en",{}).get("text",""):
        failures.append(f"console:action-availability-localization-en:{availability}")
    if availability.get("fa",{}).get("dir") != "rtl" or "برخی اقدام‌ها در وضعیت فعلی در دسترس نیستند" not in availability.get("fa",{}).get("text","") or "نشست فقط‌خواندنی است" not in availability.get("fa",{}).get("text",""):
        failures.append(f"console:action-availability-localization-fa:{availability}")
    if availability.get("enAgain") != availability.get("en"):
        failures.append(f"console:action-availability-localization-roundtrip:{availability}")
    context.close()

    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page(); prepare_quality_page(page, document, installer=False, root=root)
    application_locale = page.evaluate("""() => {
      const read=()=>({
        dir:document.documentElement.dir,
        project:String(document.querySelector('#application-workload-create-form label span')?.textContent||'').trim(),
        schema:String(document.querySelector('#application-workload-schema-digest')?.closest('label')?.querySelector('span')?.textContent||'').trim(),
        workloadAction:String(document.querySelector('#application-workload-create-form button[type="submit"]')?.textContent||'').trim(),
        deletePolicy:String(document.querySelector('#application-resource-delete-policy')?.closest('label')?.querySelector('span')?.textContent||'').trim(),
        releaseAction:String(document.querySelector('#application-release-create-form button[type="submit"]')?.textContent||'').trim(),
        bindingAction:String(document.querySelector('#application-binding-create-form button[type="submit"]')?.textContent||'').trim(),
        deploymentAction:String(document.querySelector('#application-deployment-request')?.textContent||'').trim()
      });
      state.locale='en';applyLocale();const en=read();
      state.locale='fa';applyLocale();const fa=read();
      state.locale='en';applyLocale();const enAgain=read();
      return {en,fa,enAgain};
    }""")
    expected_application_en={
        "dir":"ltr","project":"Project","schema":"Input schema digest","workloadAction":"Create workload shape",
        "deletePolicy":"Delete policy","releaseAction":"Create immutable release","bindingAction":"Create desired binding",
        "deploymentAction":"Create approval-gated deployment"
    }
    expected_application_fa={
        "dir":"rtl","project":"پروژه","schema":"هش schema ورودی","workloadAction":"ساخت قالب Workload",
        "deletePolicy":"سیاست حذف","releaseAction":"ساخت Release تغییرناپذیر","bindingAction":"ساخت Desired Binding",
        "deploymentAction":"ساخت استقرار نیازمند تأیید"
    }
    if application_locale.get("en") != expected_application_en or application_locale.get("fa") != expected_application_fa or application_locale.get("enAgain") != expected_application_en:
        failures.append(f"console:application-localization-roundtrip:{application_locale}")
    context.close()

    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page(); prepare_quality_page(page, document, installer=False, root=root)
    step_admission = page.evaluate("""async () => {
      await navigate('applications');
      state.applicationReleases=[];
      state.applicationEnvironmentBindings=[];
      state.applicationDeploymentRun=null;
      renderApplicationDeliveryJourney();
      const binding=document.querySelector('[data-application-step="binding"]');
      const workflow=document.querySelector('#application-binding-workflow');
      if(workflow)workflow.open=false;
      binding?.click();
      const blocked={
        ariaDisabled:binding?.getAttribute('aria-disabled')||'',
        reason:String(binding?.dataset?.blockedReason||''),
        workflowOpen:Boolean(workflow?.open),
        focused:document.activeElement===binding,
        errorToast:Boolean(document.querySelector('#toast-region .toast.error'))
      };
      state.applicationReleases=[{id:'quality-release',workloadImageReference:'zot.local/app@sha256:'+'a'.repeat(64)}];
      renderApplicationDeliveryJourney();
      const enabled={
        ariaDisabled:binding?.getAttribute('aria-disabled')||'',
        state:binding?.dataset?.state||'',
        reason:String(binding?.dataset?.blockedReason||'')
      };
      return {blocked,enabled};
    }""")
    blocked=step_admission.get("blocked",{})
    enabled=step_admission.get("enabled",{})
    if blocked.get("ariaDisabled") != "true" or not blocked.get("reason") or blocked.get("workflowOpen") or not blocked.get("focused") or not blocked.get("errorToast"):
        failures.append(f"console:application-step-blocked-admission:{step_admission}")
    if enabled.get("ariaDisabled") != "false" or enabled.get("state") != "current" or enabled.get("reason"):
        failures.append(f"console:application-step-enabled-admission:{step_admission}")
    context.close()

    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page(); prepare_quality_page(page, document, installer=False, root=root)
    guided = page.evaluate("""async () => {
      await navigate('applications');
      const project={id:'quality-project',displayName:'Quality project'};
      const workload={id:'quality-workload',projectId:project.id};
      const profile={id:'quality-profile',projectId:project.id};
      const release={id:'quality-release',projectId:project.id,workloadImageReference:'zot.local/app@sha256:'+'a'.repeat(64)};
      const workspace={id:'quality-workspace',projectId:project.id};
      const activeBinding={id:'quality-workspace-binding',workspaceId:workspace.id,state:'ACTIVE'};

      const read=()=>({
        library:Boolean(document.querySelector('#application-composition-library')?.open),
        release:Boolean(document.querySelector('#application-release-workflow')?.open),
        binding:Boolean(document.querySelector('#application-binding-workflow')?.open),
        deployment:Boolean(document.querySelector('#application-deployment-workflow')?.open),
        workloadTask:!document.querySelector('[data-application-library-task="workload"]')?.hidden,
        profileTask:!document.querySelector('[data-application-library-task="profile"]')?.hidden,
        prerequisite:String(document.querySelector('#application-delivery-prerequisite')?.textContent||'').trim()
      });

      state.projects=[project]; state.workspaces=[]; state.platformPolicySets=[];
      state.applicationWorkloadTypes=[]; state.applicationWorkspaceProfiles=[];
      state.applicationReleases=[]; state.applicationEnvironmentBindings=[];
      state.applicationWorkspaceBindings=[]; state.applicationDeploymentRun=null;
      renderApplicationDeliveryPrerequisite(); syncApplicationDeliveryDisclosure();
      const missingWorkload=read();

      state.applicationWorkloadTypes=[workload]; state.applicationWorkspaceProfiles=[];
      renderApplicationDeliveryPrerequisite(); syncApplicationDeliveryDisclosure();
      const missingPolicy=read();

      state.platformPolicySets=[{id:'quality-policy',projectId:project.id,digest:'sha256:'+'b'.repeat(64)}];
      renderApplicationDeliveryPrerequisite(); syncApplicationDeliveryDisclosure();
      const missingProfile=read();

      state.applicationWorkspaceProfiles=[profile];
      renderApplicationDeliveryPrerequisite(); syncApplicationDeliveryDisclosure();
      const readyForRelease=read();

      state.applicationReleases=[release]; state.workspaces=[workspace]; state.applicationWorkspaceBindings=[];
      renderApplicationDeliveryPrerequisite(); syncApplicationDeliveryDisclosure();
      const missingNamespaceBinding=read();

      state.applicationWorkspaceBindings=[activeBinding];
      renderApplicationDeliveryPrerequisite(); syncApplicationDeliveryDisclosure();
      const readyForBinding=read();

      return {missingWorkload,missingPolicy,missingProfile,readyForRelease,missingNamespaceBinding,readyForBinding};
    }""")
    if not (guided.get("missingWorkload",{}).get("library") and guided.get("missingWorkload",{}).get("workloadTask")):
        failures.append(f"console:application-guided-workload-prerequisite:{guided}")
    missing_policy=guided.get("missingPolicy",{})
    if missing_policy.get("library") or missing_policy.get("release") or "Operating policy" not in missing_policy.get("prerequisite",""):
        failures.append(f"console:application-guided-policy-prerequisite:{guided}")
    if not (guided.get("missingProfile",{}).get("library") and guided.get("missingProfile",{}).get("profileTask")):
        failures.append(f"console:application-guided-profile-prerequisite:{guided}")
    ready_release=guided.get("readyForRelease",{})
    if not ready_release.get("release") or ready_release.get("library") or ready_release.get("binding") or ready_release.get("deployment"):
        failures.append(f"console:application-guided-release-step:{guided}")
    missing_binding=guided.get("missingNamespaceBinding",{})
    if missing_binding.get("release") or missing_binding.get("binding") or missing_binding.get("deployment") or "Active namespace binding" not in missing_binding.get("prerequisite",""):
        failures.append(f"console:application-guided-namespace-prerequisite:{guided}")
    ready_binding=guided.get("readyForBinding",{})
    if not ready_binding.get("binding") or ready_binding.get("release") or ready_binding.get("deployment"):
        failures.append(f"console:application-guided-binding-step:{guided}")
    context.close()

    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page(); prepare_quality_page(page, document, installer=False, root=root)
    critical_locale = page.evaluate("""() => {
      const samples=[
        'Approve managed OKD install',
        'Approve the sealed Compact-3 install request cluster-01? The requester cannot approve their own request and execution remains evidence-tracked.',
        'Begin the bound compensation plan for application.deploy? Completed forward steps will be reversed in safe order and evidence remains attached to the same operation.',
        'Request cancellation for managed.okd.install? In-flight work is drained to a safe boundary before final cancellation.',
        'Approve this exact application deployment revision for target execution? Requester/approver separation and current authority fences are revalidated by the server.',
        'Select at least one architecture.'
      ];
      state.locale='en';const en=samples.map(localizeDynamicText);
      state.locale='fa';const fa=samples.map(localizeDynamicText);
      state.locale='en';applyLocale();
      return {en,fa};
    }""")
    expected_critical_fa=[
        "تأیید نصب مدیریت‌شدهٔ OKD",
        "درخواست مهرشدهٔ نصب Compact-3 برای cluster-01 تأیید شود؟ درخواست‌دهنده نمی‌تواند درخواست خودش را تأیید کند و اجرا با شواهد قابل پیگیری باقی می‌ماند.",
        "برنامهٔ جبرانی مقید برای application.deploy شروع شود؟ مراحل تکمیل‌شده با ترتیب امن برگردانده می‌شوند و شواهد به همان عملیات متصل می‌مانند.",
        "لغو managed.okd.install درخواست شود؟ کار در حال اجرا پیش از لغو نهایی تا مرز امن تخلیه می‌شود.",
        "این revision دقیق استقرار اپلیکیشن برای اجرای مقصد تأیید شود؟ سرور جداسازی درخواست‌دهنده/تأییدکننده و fenceهای اختیار فعلی را دوباره اعتبارسنجی می‌کند.",
        "حداقل یک معماری را انتخاب کنید.",
    ]
    if critical_locale.get("fa") != expected_critical_fa or critical_locale.get("en") is None or len(critical_locale.get("en") or []) != len(expected_critical_fa):
        failures.append(f"console:critical-interaction-localization:{critical_locale}")
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
    programmatic_behavior = page.evaluate("() => motionSafeBehavior()")
    if programmatic_behavior != "auto":
        failures.append(f"console:programmatic-reduced-motion-not-respected:{programmatic_behavior}")
    context.close()

    owner = smoke_ui.check_console(browser, root, {"width": 414, "height": 900})
    if owner.get("errors") or owner.get("horizontalOverflow") or owner.get("errorStates"):
        failures.append(f"console:data-workspace-owner:{owner}")
    return coverage


def audit_installer(browser, root: Path, failures: list[str], *, routes: list[str] | None = None, run_auxiliary: bool = True, run_matrix: bool = True) -> dict[str, int]:
    document = smoke_ui.inline_document(root / "cmd/platform-installer/static", installer=True)
    selected = list(INSTALLER_PAGES if routes is None else routes)
    coverage = _audit_route_matrix(browser, document, installer=True, routes=selected, failures=failures, root=root) if run_matrix else {
        "widths": 0, "themes": 0, "directions": 0, "routes": 0, "accessibilityRouteStates": 0,
        "expandedAccessibilityRouteStates": 0, "contrastRouteStates": 0
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
    validation = page.evaluate("""() => {
      document.querySelectorAll('.page').forEach(node=>node.classList.toggle('active',node.id==='installation'));
      if(document.documentElement.dir!=='ltr')document.querySelector('#language-toggle')?.click();
      const form=document.querySelector('#installation-form'),field=document.querySelector('#endpoint');
      if(field)field.value='';
      form?.reportValidity();
      const before=field?.id ? document.querySelector('#'+CSS.escape(field.id)+'-error')?.textContent || '' : '';
      const described=String(field?.getAttribute('aria-describedby')||'');
      const summary=String(form?.querySelector('.form-validation-summary')?.textContent||'');
      document.querySelector('#language-toggle')?.click();
      const after=field?.id ? document.querySelector('#'+CSS.escape(field.id)+'-error')?.textContent || '' : '';
      return {invalid:field?.getAttribute('aria-invalid'),before,after,described,summary,dir:document.documentElement.dir};
    }""")
    if validation.get("invalid") != "true" or not validation.get("before") or not validation.get("after") or validation.get("before") == validation.get("after") or not validation.get("described") or not validation.get("summary") or validation.get("dir") != "rtl":
        failures.append(f"installer:persistent-localized-validation:{validation}")
    context.close()

    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page(); prepare_quality_page(page, document, installer=True, root=root)
    localization = page.evaluate("""async () => {
      const settle=()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
      if(document.documentElement.dir!=='ltr'){document.querySelector('#language-toggle')?.click();await settle();}
      const read=()=>({
        dir:document.documentElement.dir,
        bucket:String(document.querySelector('[data-service="objectStorage"] [data-service-field="bucket"] span')?.textContent||'').trim(),
        prefix:String(document.querySelector('[data-service="objectStorage"] [data-service-field="prefix"] span')?.textContent||'').trim(),
        service:String(document.querySelector('[data-service="objectStorage"] h3')?.textContent||'').trim(),
        mode:String(document.querySelector('[data-service="objectStorage"] > label > span')?.textContent||'').trim()
      });
      const en=read();
      document.querySelector('#language-toggle')?.click();await settle();
      const fa=read();
      document.querySelector('#language-toggle')?.click();await settle();
      const enAgain=read();
      return {en,fa,enAgain};
    }""")
    expected_en={"dir":"ltr","bucket":"S3 bucket","prefix":"Object prefix","service":"Evidence and backup storage","mode":"Mode and provider"}
    expected_fa={"dir":"rtl","bucket":"مخزن S3","prefix":"پیشوند مسیر","service":"ذخیره‌سازی شواهد و پشتیبان","mode":"حالت و ارائه‌دهنده"}
    if localization.get("en") != expected_en or localization.get("fa") != expected_fa or localization.get("enAgain") != expected_en:
        failures.append(f"installer:generated-localization-roundtrip:{localization}")
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
        "schemaVersion": 5,
        "authority": "OPERATOR_EXPERIENCE_VIEWPORT_ACCESSIBILITY_V1",
        "disclosureAuthority": "OPERATOR_EXPERIENCE_DISCLOSURE_EXPANDED_MATRIX_V1",
        "validationAuthority": "FORM_VALIDATION_FEEDBACK_V1",
        "directionalAuthority": "RTL_DIRECTIONAL_AFFORDANCE_V1",
        "taskFirstDensityAuthority": "TASK_FIRST_PROGRESSIVE_DISCLOSURE_V1",
        "runtimeLocalizationAuthority": "RUNTIME_GENERATED_LOCALIZATION_PARITY_V1",
        "actionableEmptyStateAuthority": "ACTIONABLE_EMPTY_STATE_RECOVERY_V1",
        "applicationStepAdmissionAuthority": "APPLICATION_PROGRESSIVE_STEP_ADMISSION_V1",
        "programmaticReducedMotionAuthority": "PROGRAMMATIC_REDUCED_MOTION_V1",
        "applicationLocalizationAuthority": "APPLICATION_DELIVERY_LOCALIZATION_PARITY_V1",
        "routeJourneyFramingAuthority": "ROUTE_JOURNEY_FRAMING_V1",
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
