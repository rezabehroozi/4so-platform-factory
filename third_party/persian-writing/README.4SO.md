# persian-writing integration in 4SO Platform Factory

This directory is a pinned, curated core snapshot of `ali2000hos/persian-writing`
version 1.3.5 at commit `118c2167f30cafe18df13c0ba85f98f50dad1894`.

4SO uses it as an offline release-gate input for Persian product copy. The
integration is deliberately narrower than the full upstream package: the
Operator Console needs register, orthography and AI-tell checks, not bundled
fonts or the optional 453K-word spell-check dictionary. Those binary/data assets
are therefore not redistributed here.

Product-owned executable integration lives in `scripts/persian_writing_gate.py`.
It consumes the upstream principles plus 4SO's technical-term glossary and
fails closed on mechanical Persian errors, bureaucratic/AI-sounding product
copy, and unreviewed mixed-language grammar.

Updating this dependency requires changing `UPSTREAM.json`, reviewing upstream
rule changes, running the Persian-writing gate, localization coverage, UI smoke,
and the repository validator. No network fetch occurs at product runtime.
