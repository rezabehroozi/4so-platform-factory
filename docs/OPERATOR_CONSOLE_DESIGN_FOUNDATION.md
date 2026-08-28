# Operator Console design foundation

## Decision

4SO Platform Factory uses **TailAdmin Community Edition** as the external visual/layout reference for the Operator Console while keeping the console implementation, information architecture, workflows, authority semantics, design tokens and product identity owned by 4SO.

This is deliberately **not** a framework migration. The shipped console remains the embedded browser-native HTML/CSS/JavaScript surface already served by `platform-api`. Tailwind CSS, Alpine.js, React, Next.js, Material UI, Bootstrap and CoreUI are not introduced as runtime dependencies merely to obtain an admin-template look.

The reference is limited to reusable product-design patterns that fit a dense enterprise control plane:

- persistent high-contrast sidebar with clear active context;
- sticky top application header;
- keyboard command search (`Ctrl/Cmd+K`) for navigation;
- explicit light/dark theme control;
- restrained data-card geometry rather than decorative cards;
- compact, legible tables and status surfaces;
- consistent forms, disclosure panels and action consoles;
- responsive navigation that preserves workflow context;
- a neutral visual hierarchy suitable for long operator sessions.

4SO intentionally does **not** copy TailAdmin demo navigation, sample business domains, marketing pages, e-commerce/CRM concepts, charts without an operational consumer, or PRO-only assets/components.

## Evaluation

The three candidate families were evaluated against the current 4SO frontend boundary rather than by screenshot preference alone.

| Criterion | TailAdmin Community | CoreUI | AdminMart / Modernize |
|---|---:|---:|---:|
| Fit for dense platform operations | 9.5/10 | 9/10 | 7.5/10 |
| Modern visual hierarchy | 9.5/10 | 8/10 | 9/10 |
| Existing embedded-console fit | 10/10 when patterns are adapted | 6/10 if full Bootstrap/CoreUI runtime is adopted | 5/10 for MUI/Next-centric variants |
| Tables / data-heavy admin surfaces | 9/10 | 9.5/10 | 8/10 |
| Accessibility maturity of upstream | 8.5/10 | 10/10 | 8/10 |
| Dark-mode / layout reference quality | 9.5/10 | 9/10 | 9/10 |
| Dependency/supply-chain cost for 4SO | 10/10 with no runtime import | 6/10 with full runtime | 5/10 with full framework migration |
| Ability to remain visibly 4SO-specific | 10/10 | 8/10 | 8/10 |
| Community/free licensing fit | MIT Community | MIT free template | MIT free variants; premium differs |

### Why TailAdmin wins

TailAdmin's current dashboard family is closest to the actual 4SO workload: data-heavy dashboards, multiple shell/layout variations, AI surfaces, API-key/integration pages, tables, dark mode and compact administrative flows. Its Community HTML edition is MIT and therefore gives the project a legally simple reference point.

4SO does not need TailAdmin's build/runtime stack. Importing Alpine/Tailwind/Webpack solely for visual parity would increase frontend supply-chain and build complexity without improving the product authority model. The correct reuse level is therefore **design language and interaction patterns**, reimplemented with existing 4SO primitives.

### Why not CoreUI as the primary shell

CoreUI is the strongest of the candidates for a large prebuilt enterprise component library and explicit accessibility/WCAG/ARIA posture. It remains a useful audit reference for component and accessibility behavior. However, adopting the full CoreUI shell would make the current console Bootstrap/CoreUI-centric and would push the UI toward a more generic Bootstrap-admin character. 4SO does not currently need that framework migration.

### Why not AdminMart / Modernize as the primary shell

AdminMart's Modernize family is polished and offers many framework variants, but its strongest implementations are oriented around React/Next/MUI or premium template packages. The free Tailwind edition is materially smaller than its premium offering and does not justify changing the current embedded frontend architecture. Its visual tone also skews more toward SaaS/analytics than an infrastructure control plane.

## 4SO-specific visual identity

The final console must not look like a renamed TailAdmin demo. The following are product-owned invariants:

1. Navigation is organized around 4SO operator journeys and permissions, never template demo categories.
2. Every metric/card must have an operational consumer; decorative analytics are not admitted.
3. Mutations stay inside `Select -> Inspect -> Allowed Action -> Input -> Impact Preview -> Approval -> Execute -> Evidence` workflows.
4. Authority, stale/loading/error/forbidden state is represented truthfully; empty and failed data are never both rendered as `0`.
5. AI surfaces remain advisory and evidence-linked. There is no generic LLM shell/terminal button.
6. RTL/LTR are first-class and tested at the same responsive widths.
7. Dense pages favor scanability, progressive disclosure and strong typographic hierarchy over large marketing whitespace.
8. Destructive actions are visually separated from routine controls and continue to use existing RBAC/confirmation/durable-operation boundaries.
9. System state uses restrained semantic tokens; excessive gradients, glass effects and animation are prohibited.
10. Design tokens, component behavior and responsive breakpoints remain owned and testable in 4SO source.

## Implemented foundation

The 0.0.218 design foundation adds or standardizes:

- high-contrast product sidebar and active navigation state;
- sticky application header and compact operator context;
- global navigation-only command palette with `Ctrl/Cmd+K`;
- persisted explicit light/dark theme control;
- denser metric, panel, table and action-console treatment;
- responsive command/search behavior;
- 320px mobile overflow closure;
- browser smoke coverage for command search, theme switching and RTL/LTR behavior;
- Release Gate process isolation per Playwright viewport to avoid cumulative driver state from becoming false UI evidence.

This foundation does not change API authority or mutation permissions.

## Licensing and provenance

No TailAdmin PRO asset is used. TailAdmin Community is an MIT-licensed reference. If future implementation copies source rather than independently implementing a pattern, the upstream MIT copyright/license notice must be retained in the repository and release notices/SBOM as appropriate.

CoreUI and AdminMart are evaluation references only and are not current runtime dependencies.
