#!/usr/bin/env python3
"""Vendored from ali2000hos/persian-writing v1.3.5 (commit 118c2167...)."""
import argparse, re, sys, unicodedata

PERSIAN = r'؀-ۿ‌'
FA_LETTER = r'[ء-غف-ئپچژکگیة]'
ZWNJ = '‌'
ISSUES = []

def record(kind, line_no, snippet, suggestion):
    ISSUES.append((kind, line_no, snippet.strip()[:80], suggestion))

ARABIC_MAP = {'ي': 'ی', 'ك': 'ک', 'ىٰ': 'ی', 'ى': 'ی',
              '٠': '۰', '١': '۱', '٢': '۲', '٣': '۳', '٤': '۴',
              '٥': '۵', '٦': '۶', '٧': '۷', '٨': '۸', '٩': '۹'}
ENCLITIC_BLACKLIST = {'به', 'که', 'چه', 'نه', 'سه', 'آنچه', 'اینکه', 'گه'}
TANVIN_NEEDED = {'لطفا': 'لطفاً', 'حتما': 'حتماً', 'واقعا': 'واقعاً', 'اصلا': 'اصلاً',
                 'کاملا': 'کاملاً', 'مثلا': 'مثلاً', 'معمولا': 'معمولاً',
                 'تقریبا': 'تقریباً', 'دقیقا': 'دقیقاً', 'فعلا': 'فعلاً',
                 'قطعا': 'قطعاً', 'اتفاقا': 'اتفاقاً', 'احتمالا': 'احتمالاً',
                 'مخصوصا': 'مخصوصاً', 'اساسا': 'اساساً', 'عملا': 'عملاً'}
FA_B_L = r'(?<![؀-ۿ‌])'
FA_B_R = r'(?![؀-ۿًٌٍَُِّ‌])'
_HE_NOUNS = set("""خانه خونه نامه برنامه هفته پروژه مدرسه نقشه جمعه قهوه بچه شنبه دقیقه
ثانیه پنجره اندازه سفره کوچه میوه لحظه جمله مرحله نتیجه مقاله هزینه گزینه نمونه زمینه
دسته بسته پوشه شبکه حوزه دوره چهره سلیقه علاقه سابقه تجربه قطعه منطقه فاصله مجموعه
موسسه مسئله مساله وسیله هدیه اجاره اداره اشاره ستاره کناره ساده آماده ایده شماره
اجازه انگیزه اندیشه ترانه بهانه نشانه خاطره پرونده آینده گذشته رابطه ضابطه قاعده
مبادله معامله محاسبه مطالعه مراجعه مصاحبه مقایسه مناقصه مزایده""".split())
_PRON = r'(?:من|تو|ما|شما|او|اون|ایشون|اونا|اینا|خودم|خودت|خودش|این|آن)'
_DICT_RANK_FA = {}

def _load_ranks():
    global _DICT_RANK_FA
    if _DICT_RANK_FA:
        return _DICT_RANK_FA
    import os
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'assets', 'persian_words.txt')
    if os.path.isfile(path):
        with open(path, encoding='utf-8') as fh:
            for i, line in enumerate(fh):
                w = line.strip()
                if w and w not in _DICT_RANK_FA:
                    _DICT_RANK_FA[w] = i
    return _DICT_RANK_FA

def find_hekasre(text):
    rank = _load_ranks()
    INF = 10 ** 9
    if not rank:
        return []
    r = lambda w: rank.get(w, INF)
    out = []
    for m in re.finditer(r'(?<![‌آ-ی])([آ-ی]{2,})ه\s+([آ-ی]{2,})', text):
        stem, nxt = m.group(1), m.group(2)
        whole = stem + 'ه'
        if whole in _HE_NOUNS or r(stem) == INF:
            continue
        if r(whole) == INF:
            out.append((m.group(0), f'{stem}ِ {nxt}', 'A'))
    for m in re.finditer(r'(?<![‌آ-ی])([آ-ی]{2,})ه\s+(' + _PRON + r')(?![آ-ی])', text):
        stem, nxt = m.group(1), m.group(2)
        whole = stem + 'ه'
        if whole in _HE_NOUNS or r(stem) == INF or r(whole) == INF:
            continue
        if r(whole) > r(stem) * 3 and r(whole) > 20000:
            out.append((m.group(0), f'{stem}ِ {nxt}', 'B'))
    return out

def fix_safe(text):
    for a, p in ARABIC_MAP.items():
        text = text.replace(a, p)
    text = re.sub(r'\b(ن?می) (?=' + FA_LETTER + ')', r'\1' + ZWNJ, text)
    text = re.sub(r'(' + FA_LETTER + r') (ها(?:ی|یی)?)(?![' + PERSIAN.strip('[]') + r'])',
                  r'\1' + ZWNJ + r'\2', text)
    def _encl(m):
        w = m.group(1)
        return m.group(0) if w in ENCLITIC_BLACKLIST else w + ZWNJ + m.group(2)
    text = re.sub(r'\b(' + FA_LETTER + r'+ه) (ام|ات|اش|ای|اید|اند)\b', _encl, text)
    text = re.sub(r'(?<=[' + PERSIAN + r'])\s*\?', '؟', text)
    text = re.sub(r'(?<=[' + PERSIAN + r'])\s*,\s*(?=[' + PERSIAN + r'])', '، ', text)
    text = re.sub(r'(?<=[' + PERSIAN + r'])\s*;\s*(?=[' + PERSIAN + r'])', '؛ ', text)
    text = re.sub(r' +([،؛؟!])', r'\1', text)
    text = re.sub(r'([،؛])(?=[' + PERSIAN + r'])', r'\1 ', text)
    text = re.sub(r'(?<=\S)  +(?=\S)', ' ', text)
    for bare, correct in TANVIN_NEEDED.items():
        text = re.sub(FA_B_L + bare + FA_B_R, correct, text)
    return text

def fix_aggressive(text):
    text = re.sub(r'(' + FA_LETTER + r'{2,}) (تر|ترین)\b(?! و تازه)',
                  r'\1' + ZWNJ + r'\2', text)
    text = re.sub(r'"([^"\n]*' + FA_LETTER + r'[^"\n]*)"', r'«\1»', text)
    return text

def _skip_token(tok):
    return bool(re.search(r'https?://|www\.|@|[/\\]|\.[a-z]{2,}|`', tok)
                or re.fullmatch(r'\+?\d+(\.\d+)+[.,;،]?', tok))

def fix_digits(text):
    def conv(tok):
        return tok.translate(str.maketrans('0123456789', '۰۱۲۳۴۵۶۷۸۹'))
    out_lines = []
    for line in text.split('\n'):
        has_fa = re.search(FA_LETTER, line)
        out_lines.append(' '.join(
            conv(t) if has_fa and re.search(r'[0-9]', t) and not _skip_token(t) else t
            for t in line.split(' ')))
    return '\n'.join(out_lines)

ATTACHED_MI = re.compile(r'\b(می(?:شود|شوند|شد|کند|کنند|کرد|گوید|گویند|گفت|باشد|باشند|'
                         r'تواند|توانند|توانید|خواهد|خواهند|خواهیم|رود|روند|آید|آیند|'
                         r'دهد|دهند|گیرد|گیرند|ماند|شویم|کنیم|رویم|بینید|بینیم|دانید|دانیم))\b')
TANVIN_FA = {'گاهاً': 'گاهی', 'گاها': 'گاهی', 'دوماً': 'دوم اینکه / ثانیاً',
             'سوماً': 'سوم اینکه / ثالثاً', 'ناچاراً': 'به‌ناچار', 'زباناً': 'به زبان',
             'تلفناً': 'تلفنی', 'خواهشاً': 'خواهش می‌کنم'}

def check_remaining(text):
    for i, line in enumerate(text.split('\n'), 1):
        if not re.search(FA_LETTER, line):
            continue
        for ch, name in [('—', 'em dash'), ('–', 'en dash')]:
            if ch in line:
                record('dash', i, line, f'{name}: replace with «،»/«؛»/() or restructure')
        if 'ة' in line:
            record('arabic-teh', i, line, 'ة: use ه/هٔ unless quoting Arabic')
        for m in ATTACHED_MI.finditer(line):
            record('attached-mi', i, line, f'{m.group(0)}: formal register needs می‌{m.group(0)[2:]}')
        scratch = line
        for bad in sorted(TANVIN_FA, key=len, reverse=True):
            if bad in scratch:
                record('fake-tanvin', i, line, f'{bad} → {TANVIN_FA[bad]}')
                scratch = scratch.replace(bad, '')
        for bare, correct in TANVIN_NEEDED.items():
            if re.search(FA_B_L + bare + FA_B_R, line):
                record('missing-tanvin', i, line, f'{bare} → {correct}')
        if re.search(r'!{2,}', line):
            record('multi-bang', i, line, 'one ! maximum')
        for m in re.finditer(r'\b(می‌گردد|می‌گردند|گردید(?:ه است)?|گردیدند)\b', line):
            record('bureaucratic-verb', i, line,
                   f'{m.group(0)}: fossil register — use می‌شود/شد (unless گردیدن = چرخیدن)')
        for hit, fix, tier in find_hekasre(line):
            conf = 'likely' if tier == 'A' else 'possible'
            record('hekasre', i, line,
                   f'«{hit}» → «{fix}» ({conf} هکسره: ezafe kasre written as ـه)')
        for m in re.finditer(r'([آ-ی]{2,})ِ\s*(?=[.!؟\n]|$)', line):
            record('hekasre', i, line,
                   f'«{m.group(0).strip()}» ends a clause with a kasre — predicate «است» '
                   f'is written «{m.group(1)}ه» (خوبه), not with ـِ')
        if re.search(r'(?<=[' + PERSIAN + r'])\s*[,;?]|[,;?]\s*(?=[' + PERSIAN + r'])', line):
            record('latin-punct', i, line, 'Latin ,;? in Persian context → ، ؛ ؟')
        for a in ARABIC_MAP:
            if a in line:
                record('arabic-char', i, line, f'{a} → {ARABIC_MAP[a]}')
        if re.search(r'\b(ن?می) ' + FA_LETTER, line):
            record('zwnj-mi', i, line, 'می + space → می + ZWNJ (نیم‌فاصله)')
        if re.search(r'(' + FA_LETTER + r') ها\b', line):
            record('zwnj-ha', i, line, 'plural ها: use ZWNJ (کتاب‌ها) — ignore if emphasis particle')
        if re.search(r'(' + FA_LETTER + r'{2,}) (تر|ترین)\b(?! و تازه)', line):
            record('zwnj-tar', i, line, 'comparative تر/ترین: use ZWNJ (بزرگ‌تر)')
        if re.search(r'"[^"\n]*' + FA_LETTER, line):
            record('quotes', i, line, 'straight quotes around Persian → «گیومه»')
        for tok in line.split():
            if (re.search(r'[0-9]', tok) and re.search(FA_LETTER, line)
                    and not _skip_token(tok)):
                record('latin-digits', i, line, f'{tok}: Persian digits in Persian prose (or --digits)')
                break

def rhythm_report(text):
    import statistics as stats
    fa_sents = [s.strip() for s in re.split(r'[.!?؟\n]+', re.sub(r'[#*>`]', ' ', text))
                if len(s.strip().split()) >= 2 and re.search(FA_LETTER, s)]
    lengths = [len(s.split()) for s in fa_sents]
    out = []
    if len(lengths) < 8:
        return [('too-short', f'{len(lengths)} sentences — rhythm needs ~8+ to mean anything')]
    mean = stats.mean(lengths)
    cv = stats.pstdev(lengths) / mean if mean else 0
    short = sum(1 for x in lengths if x < 8)
    long_ = sum(1 for x in lengths if x > 25)
    out.append(('measured', f'{len(lengths)} sentences | mean {mean:.1f} words | variation {cv:.2f} | range {min(lengths)}–{max(lengths)}'))
    if cv < 0.35:
        out.append(('uniform-rhythm', f'variation {cv:.2f} is low — reread for machine-flat prose'))
    if short == 0:
        out.append(('no-short-sentence', 'no sentence under 8 words'))
    if long_ == 0 and mean < 20:
        out.append(('no-long-sentence', 'every sentence is short-to-medium'))
    starts = [s.split()[0] for s in fa_sents if s.split()]
    if starts and len(set(starts)) < len(starts) * 0.6:
        rep = max(set(starts), key=starts.count)
        out.append(('repeated-openings', f'sentences repeat opening word "{rep}" ×{starts.count(rep)}'))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('files', nargs='+')
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--fix', action='store_true')
    ap.add_argument('--aggressive', action='store_true')
    ap.add_argument('--digits', action='store_true')
    ap.add_argument('--rhythm', action='store_true')
    args = ap.parse_args()
    exit_code = 0
    for path in args.files:
        ISSUES.clear()
        text = sys.stdin.read() if path == '-' else open(path, encoding='utf-8').read()
        text = unicodedata.normalize('NFC', text)
        if args.fix:
            text = fix_safe(text)
            if args.aggressive: text = fix_aggressive(text)
            if args.digits: text = fix_digits(text)
            if path == '-': sys.stdout.write(text)
            else: open(path, 'w', encoding='utf-8').write(text)
            check_remaining(text)
        else:
            check_remaining(text)
            if fix_safe(text) != text:
                record('fixable', 0, '(multiple)', 'safe auto-fixes available: rerun with --fix')
        print(f'== {path}: {len(ISSUES)} issues ==', file=sys.stderr)
        if args.rhythm:
            for kind, msg in rhythm_report(text): print(f'  [{kind}] {msg}', file=sys.stderr)
        for kind, ln, snip, sug in ISSUES:
            print(f'  [{kind}] L{ln}: {snip}\n      → {sug}', file=sys.stderr)
        if ISSUES: exit_code = 1
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
