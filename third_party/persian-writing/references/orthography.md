# Persian orthography: the mechanical layer

Correct orthography is what separates a professional Persian document from a
typed-in-a-hurry one. Readers may not name the rule, but they feel it. All of
this is enforceable: `scripts/persian_cleanup.py --edit` fixes the mechanical
layer automatically; `scripts/fa_lint.py --check` reports what needs judgment.

## 1. ZWNJ — نیم‌فاصله (U+200C)

The zero-width non-joiner separates morphemes without a visual gap while
preventing letter joining.

Required ZWNJ positions:

| Pattern | Wrong | Right |
|---|---|---|
| می/نمی + verb | می شود، نمی توانم، میشود | می‌شود، نمی‌توانم |
| Plural ها | کتاب ها، سایت های | کتاب‌ها، سایت‌های |
| تر / ترین | بزرگ تر، مهم ترین | بزرگ‌تر، مهم‌ترین |
| Enclitic pronouns after ه | خانه ام، پروژه اش | خانه‌ام، پروژه‌اش |
| Compound prefixes | بی دقت، هم زمان | بی‌دقت، هم‌زمان |
| Compound words | وب سایت، صفحه بندی، نرم افزار | وب‌سایت، صفحه‌بندی، نرم‌افزار |
| ای after ه | حرفه ای، هفته ای | حرفه‌ای، هفته‌ای |

## 2. Persian characters, not Arabic

| Use (Persian) | Never (Arabic) |
|---|---|
| ی U+06CC | ي U+064A |
| ک U+06A9 | ك U+0643 |
| ۀ/هٔ (or ه‌ی) | ة U+0629 |
| ۴۵۶ U+06F4.. | ٤٥٦ U+0664.. |

## 3. Digits

- Persian digits ۰۱۲۳۴۵۶۷۸۹ inside Persian prose.
- Latin digits stay Latin inside URLs, emails, international phone numbers,
  code, version strings and file names.
- Never Arabic-Indic variants (٤ ٥ ٦).
- Percent: «۲۰٪» or «۲۰ درصد».

## 4. Punctuation

| Persian | Replaces | Note |
|---|---|---|
| ، U+060C | , | comma |
| ؛ U+061B | ; | semicolon |
| ؟ U+061F | ? | question mark |
| «...» | "..." | quotes |
| … | ... | ellipsis |

Rules:
- No space before punctuation, one space after.
- One exclamation mark maximum.
- Em/en dashes are not used in Persian prose. Restructure or use Persian punctuation.
- Latin fragments keep Latin punctuation inside the fragment.

## 5. Ezafe and هکسره

Never write the ezafe kasre as «ـه». «کتابِ من» is correct; «کتابه من» is not.
The «ـه» ending belongs to colloquial «است» only: «این کتابه» = «این کتاب است».
In formal product copy use «است» rather than the colloquial clitic.

## 6. Spacing hygiene

- Exactly one space between words.
- No space inside «گیومه».
- Parentheses: space outside, none inside.
- Latin↔Persian boundary: one space.

## 7. Numbers as words

Formal prose may spell short counts as words; tables, prices and stats use digits.
Do not mix numbering styles inside one list.

## 8. Common corrections

| Wrong | Right |
|---|---|
| میخواهم | می‌خواهم |
| کتابها | کتاب‌ها |
| عليرضا | علیرضا |
| لطفا | لطفاً |
| گاهاً | گاهی |
| دوماً | دوم اینکه / ثانیاً |
| "نقل قول" | «نقل قول» |
| 20 درصد | ۲۰ درصد |
