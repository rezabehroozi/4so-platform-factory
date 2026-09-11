# Persian writing style: registers and de-AI-ing

AI Persian often fails by being too formal, too کتابی and too predictable. The
fix is not to make everything colloquial. Pick the correct register, then strip
the bureaucratic and generated-text tells.

## Register detection

For an enterprise Operator Console, installer and technical product copy, the
baseline is **formal-but-human**: full written verb forms, no slang, short direct
sentences, clear state and next action, and established technical nouns only
when they improve comprehension.

Use this order:

1. Explicit register instruction wins.
2. Classify the deliverable, not the tone of the request.
3. Consider audience and destination.
4. Keep one register per artifact.
5. For high-stakes ambiguous third-party copy, ask rather than guess.
6. With no signal, use formal-but-human.

Formal Persian does not mean bureaucratic Persian. Prefer «است، شد، کرد» over
«می‌باشد، گردید، به عمل آورد». One idea per sentence. State concrete impact
instead of ceremonial claims.

## Persian AI tells to remove

1. Copula inflation: می‌باشد، به شمار می‌رود، محسوب می‌شود when «است» is enough.
2. Filler announcements: لازم به ذکر است، شایان ذکر است، قابل توجه است که.
3. Significance inflation: نقش بسزایی، اهمیت ویژه، گامی مهم در راستای.
4. Generic openers/closers: در دنیای امروز، در نهایت می‌توان گفت، به طور کلی.
5. «در راستای» when «برای» says the same thing.
6. Promotional emptiness without evidence.
7. Formulaic rule-of-three lists.
8. Overused «نه تنها ... بلکه».
9. Tacked-on analysis clauses: «که نشان‌دهنده‌ی ... است» without evidence.
10. Vague authority: «کارشناسان معتقدند» without a named source.
11. False ranges: «از X گرفته تا Y» for unrelated items.
12. Em/en dash rhythm in Persian prose.
13. Translationese/calques.
14. Repeated «همچنین / علاوه بر این / افزون بر آن» openings.
15. Fake tanvin on Persian words: گاهاً، دوماً, etc.
16. Bold-header bullet furniture when prose is clearer.
17. Chatbot residue: «سؤال بسیار خوبی است»، «خوشحال می‌شوم کمک کنم».
18. Uniform, overly predictable wording and paragraph rhythm.

## What not to flag

- Correct formal Persian is not an AI tell.
- One polite phrase is normal in the right artifact.
- Established loanwords and product/protocol names are normal.
- Do not force unnatural pure-Persian replacements for familiar technical terms.
- One isolated «همچنین» or one exclamation is not evidence of poor writing.

## Product-writing process

1. Identify the operator task and expected result.
2. Draft in formal-but-human Persian.
3. Remove implementation-first wording that does not help the operator act.
4. Run mechanical orthography checks.
5. Scan for bureaucratic/AI tells.
6. Preserve limitations, prerequisites, blocked states and evidence truth.
7. Read the final text as an Iranian operator: if it sounds translated or robotic,
   rewrite it before release.
