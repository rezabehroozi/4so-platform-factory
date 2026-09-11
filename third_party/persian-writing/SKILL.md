---
name: persian-writing
description: >
  Write natural, human-sounding Persian (Farsi) and build correct right-to-left
  Persian deliverables. Use for ANY task involving Persian text or an Iranian
  audience: writing, editing, translating, humanizing, SEO content and
  copywriting (سئو، کپی‌رایتینگ، لندینگ), academic papers/theses, and Persian
  output in Word/.docx, PDF, PowerPoint, HTML, Excel, images/posters, emails,
  social posts. Covers register detection (رسمی/اداری/محاوره/علمی — errors here
  are costly), Persian AI-tell removal, orthography (نیم‌فاصله/ZWNJ، اعداد
  فارسی، «گیومه»), cleanup and spell-check (ویرایش، پاکسازی — bundled
  paknevis+davat toolkit), RTL layout/pagination fixes, and Persian fonts
  (Vazirmatn bundled). Trigger whenever you see Persian/Arabic script or words
  like فارسی, Farsi, Persian, Iran, RTL, راست‌چین, نیم‌فاصله, ویرایش, مقاله,
  پایان‌نامه, سئو, کپشن, Vazirmatn — even if the user never mentions this skill.
metadata:
  version: 1.3.5
license: MIT (bundled fonts under SIL OFL)
compatibility: >
  Any agent that reads Markdown skills (Claude, Claude Code, Cursor, Codex,
  custom harnesses; chat-only AIs via universal/persian-writing-universal.md).
  Scripts: Python 3.8+ stdlib only. docx/pptx→PDF conversion: LibreOffice +
  installed fonts. PDF checks: poppler-utils, pypdf, or PyMuPDF (any one).
---

# Persian Writing & RTL Documents

Two failure modes make Persian output look machine-made, and they are independent:

1. **The prose sounds like AI.** Technically correct, but stiff, کتابی, inflated —
   no Iranian would write it that way.
2. **The layout betrays the text.** Persian rendered left-aligned, Arabic ي/ك glyphs,
   Latin digits breaking RTL flow, headings orphaned at page bottoms, fonts falling
   back to DejaVu.

Fixing one without the other still produces something a native reader screenshots
and laughs at. This skill fixes both. Work through the two checklists below, and
read the reference file for your output format before generating anything.

## Step 0: Route by task

| Task | Read |
|---|---|
| Any Persian prose (always) | `references/writing-style.md` |
| Mechanical correctness (always) | `references/orthography.md` |
| Academic: paper, thesis, report, مقاله/پایان‌نامه | `references/academic.md` |
| Educational/technical content, docs, product pages, how-to | `references/content-structures.md` |
| Telegram, Instagram, captions, carousels, reels, stories | `references/social-channels.md` |
| SEO content, blog for search, landing/ad copy, کپشن فروش | `references/seo-copywriting.md` |
| Cleanup/normalize/spell-check existing text (ویرایش، پاکسازی) | `references/cleanup/paknevis-rules.md` + `usage-patterns.md` |
| Choosing/embedding fonts | `references/fonts.md` |
| Word/.docx or docx→PDF | `references/docx-pdf.md` |
| PowerPoint/.pptx | `references/pptx.md` |
| HTML, email templates, HTML→PDF | `references/html-css.md` |
| Images/posters (PIL), new PDFs (reportlab), Excel | `references/format-skills-fa.md` |

**Visual neutrality — read before copying any code example.** This skill styles
NOTHING. It governs direction, spacing, fonts-for-shaping and text — never
colors, accent bars, card backgrounds, or a house look. Default output is black
text on default background, no accent color. Take colors and visual form only
from the user's explicit request, an attached brand/theme skill, or an input
template being matched.

## Writing: the five-second summary

1. **Detect register before writing.** Classify the deliverable, not the tone of
   the request. Professional product UI and B2B copy are formal-but-human.
2. **Ban bureaucratic tells:** می‌باشد، لازم به ذکر است، در راستای، از اهمیت
   ویژه‌ای برخوردار است، نقش بسزایی ایفا می‌کند.
3. **Ban AI tells:** em dashes, formulaic triads, نه تنها ... بلکه, vague authority,
   generic openers and generic conclusions.
4. **Hold one point of view.** Explain facts impersonally, address the reader
   directly for user actions, and use «ما» only for the organization's actions.
5. **Separate teaching from selling.** State the problem before the product and
   preserve limitations and prerequisites.
6. **Claim only what the source supports.** Never invent statistics, versions,
   prices, quotes, or operational success.
7. **The native test:** would an Iranian reader call it «متن هوش مصنوعی»? If yes,
   rewrite it before delivery.
8. **Numbers, punctuation and spacing** must follow Persian orthography.

## Orthography: non-negotiables

1. **ZWNJ (نیم‌فاصله, U+200C)** — می‌شود نه می شود؛ کتاب‌ها نه کتاب ها؛
   بزرگ‌تر، خانه‌ام، به‌عنوان.
2. **Persian characters only:** ی (U+06CC) not ي، ک (U+06A9) not ك.
3. **Persian digits** ۰۱۲۳۴۵۶۷۸۹ inside Persian prose. Latin digits stay in URLs,
   emails, code and version numbers.
4. **Persian punctuation:** ، ؛ ؟ and «گیومه» for quotes. No space before, one after.
5. **No em/en dashes** in Persian prose — use «،» or restructure.
6. **Never letter-space Persian.**

The upstream package uses `scripts/persian_cleanup.py` and `scripts/fa_lint.py`.
The 4SO integration vendors `fa_lint.py` and adds a product-owned gate at
`../../scripts/persian_writing_gate.py` so release validation is network-free.

## Documents: rules that always apply

1. RTL means START, not RIGHT.
2. Persian runs use RTL-aware shaping and a Persian-capable font.
3. Sections and RTL tables must carry bidi metadata.
4. Persian numbered content uses Persian digits; avoid Latin numbering that flips flow.
5. Fix document defaults before adding content.
6. Avoid orphan headings and split cards/boxes.
7. Verify generated artifacts, not only source code.
