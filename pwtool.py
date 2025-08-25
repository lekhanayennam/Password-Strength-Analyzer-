#!/usr/bin/env python3
"""
Password Strength Analyzer & Custom Wordlist Generator (CLI)

Features
- Analyze password strength using zxcvbn (if available) with fallback to entropy estimate
- Generate custom wordlists from user-provided clues (name, pet, dates, extras)
- Variations: case toggles, simple/extended leetspeak, append years, separators, token combos
- Profiles: simple | balanced | aggressive (controls depth and size)
- Export to .txt in a cracking-tool-friendly format (one candidate per line)

Usage examples
  python pwtool.py --password "Winter2025!" --name "Lekhana" --pet "Bruno" --date "2001-06-15" \
                   --extra "cyber" --profile balanced --outfile out.txt

  python pwtool.py --password "P@ssw0rd" --name "Arjun Rao" --date 2001 \
                   --append-years 1995-2030 --leet extended --max 50000

Legal/Ethical Notice: Use ONLY on systems you own or are explicitly authorized to test.
Misuse may be illegal. This tool is for defensive security auditing and learning.
"""
from __future__ import annotations

import argparse
import itertools
import math
import os
import re
import sys
from typing import Iterable, List, Set, Dict

# Optional: zxcvbn import (supports both package names)
_ZXCVBN_AVAILABLE = False
try:
    from zxcvbn import zxcvbn as _zxcvbn
    _ZXCVBN_AVAILABLE = True
except Exception:
    try:
        # Some environments expose as zxcvbn.zxcvbn
        import zxcvbn as _zxcvbn_mod  # type: ignore
        def _zxcvbn(pw, user_inputs=None):
            return _zxcvbn_mod.zxcvbn(pw, user_inputs=user_inputs)
        _ZXCVBN_AVAILABLE = True
    except Exception:
        _ZXCVBN_AVAILABLE = False

# ---------------------------- Utility helpers ---------------------------- #

def parse_years_arg(arg: str | None, profile: str) -> List[str]:
    """Parse years like '1990-2028,2030,99' -> list of strings.
    If arg is None, return profile defaults.
    """
    if arg:
        years: Set[str] = set()
        parts = [p.strip() for p in arg.split(',') if p.strip()]
        for p in parts:
            if '-' in p:
                a, b = p.split('-', 1)
                try:
                    start = int(a)
                    end = int(b)
                    if start > end:
                        start, end = end, start
                    for y in range(start, end + 1):
                        years.add(str(y))
                        # Also add last two digits if >= 2000 (common pattern)
                        if y >= 1970:
                            years.add(str(y)[-2:])
                except ValueError:
                    continue
            else:
                if p.isdigit():
                    y = int(p)
                    years.add(str(y))
                    if y >= 1970:
                        years.add(str(y)[-2:])
        return sorted(years)
    # Defaults by profile
    from datetime import datetime
    now = datetime.now()
    current_year = now.year
    if profile == 'simple':
        rng = range(current_year - 4, current_year + 1)  # last 5 years
    elif profile == 'aggressive':
        rng = range(1990, current_year + 1)
    else:  # balanced
        rng = range(current_year - 9, current_year + 1)  # last 10 years
    years = {str(y) for y in rng}
    years.update({str(y)[-2:] for y in rng})
    return sorted(years)


def tokenize_inputs(name: str | None, pet: str | None, date: str | None, extras: List[str]) -> List[str]:
    tokens: Set[str] = set()
    def add_token(t: str):
        t = t.strip()
        if t:
            tokens.add(t)

    for text in [name, pet]:
        if text:
            # split on whitespace and punctuation
            parts = re.split(r"[\s_\-\.]+", text.strip())
            for p in parts:
                add_token(p)
    if date:
        # Accept formats like YYYY, DDMMYYYY, YYYYMMDD, DD-MM-YYYY, etc.
        only_digits = re.sub(r"\D", "", date)
        if only_digits:
            add_token(only_digits)
            # Common rearrangements
            if len(only_digits) == 8:
                yyyy = only_digits[0:4]
                mm = only_digits[4:6]
                dd = only_digits[6:8]
                add_token(dd + mm + yyyy)
                add_token(mm + dd + yyyy)
                add_token(yyyy + mm + dd)
                add_token(dd + mm + only_digits[2:4])  # ddmmyy
                add_token(mm + dd + only_digits[2:4])
            if len(only_digits) == 4:  # maybe year
                add_token(only_digits[-2:])
    for e in extras:
        add_token(e)
    return sorted(tokens)


def case_variants(s: str) -> Set[str]:
    return {s, s.lower(), s.upper(), s.title()}


_LEET_MAP: Dict[str, str] = {
    'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7', 'l': '1'
}


def leet_variants(s: str, mode: str = 'basic', cap: int = 32) -> Set[str]:
    """Return leetspeak variants.
    - basic: single pass replacing all mapped letters
    - extended: generate several combinations but cap the total to avoid explosion
    """
    variants: Set[str] = {s}
    if mode not in {'basic', 'extended'}:
        return variants

    # Basic: single full replacement pass
    trans = []
    for ch in s:
        repl = _LEET_MAP.get(ch.lower())
        trans.append(repl if repl else ch)
    variants.add(''.join(trans))

    if mode == 'extended':
        # Generate additional variants by replacing subsets
        # We iterate letters and progressively replace; cap total size
        indices = [i for i, ch in enumerate(s) if ch.lower() in _LEET_MAP]
        for r in range(1, min(3, len(indices)) + 1):  # replace up to 3 positions
            for combo in itertools.combinations(indices, r):
                lst = list(s)
                for i in combo:
                    lst[i] = _LEET_MAP.get(lst[i].lower(), lst[i])
                variants.add(''.join(lst))
                if len(variants) >= cap:
                    return variants
    return variants


def estimate_entropy_bits(password: str) -> float:
    """Rough entropy estimate using character set size and length.
    This is a *very rough* upper bound and not a replacement for zxcvbn.
    """
    if not password:
        return 0.0
    lowers = any(c.islower() for c in password)
    uppers = any(c.isupper() for c in password)
    digits = any(c.isdigit() for c in password)
    symbols = any(not c.isalnum() for c in password)
    pool = 0
    if lowers:
        pool += 26
    if uppers:
        pool += 26
    if digits:
        pool += 10
    if symbols:
        pool += 33  # conservative ASCII symbol count
    pool = max(pool, 1)
    return len(password) * math.log2(pool)


def analyze_password(password: str, user_inputs: List[str]) -> Dict:
    """Return analysis dict with common fields regardless of backend.
    Keys: backend, score, guesses, crack_times, feedback, entropy_bits
    """
    out = {
        'backend': 'entropy',
        'score': None,
        'guesses': None,
        'crack_times': None,
        'feedback': [],
        'entropy_bits': round(estimate_entropy_bits(password), 2),
    }
    if _ZXCVBN_AVAILABLE:
        try:
            res = _zxcvbn(password, user_inputs=user_inputs)
            out.update({
                'backend': 'zxcvbn',
                'score': res.get('score'),
                'guesses': res.get('guesses'),
                'crack_times': res.get('crack_times_display') or res.get('crack_times_seconds'),
                'feedback': (res.get('feedback') or {}).get('suggestions', []),
            })
        except Exception:
            pass
    return out


def capped_extend(dst: Set[str], src: Iterable[str], cap: int):
    for x in src:
        if len(dst) >= cap:
            break
        dst.add(x)


def generate_wordlist(
    name: str | None,
    pet: str | None,
    date: str | None,
    extras: List[str],
    profile: str = 'balanced',
    leet: str = 'basic',
    append_years: List[str] | None = None,
    separators: List[str] | None = None,
    minlen: int = 4,
    maxlen: int = 24,
    max_count: int = 50000,
) -> List[str]:
    """Generate a wordlist according to the chosen profile.
    Returns up to max_count unique candidates within [minlen, maxlen].
    """
    if profile not in {'simple', 'balanced', 'aggressive'}:
        profile = 'balanced'

    if separators is None:
        if profile == 'simple':
            separators = ['', '!', '1']
        elif profile == 'aggressive':
            separators = ['', '!', '@', '#', '_', '.', '-', '123']
        else:
            separators = ['', '!', '@', '_', '123']

    years = append_years or parse_years_arg(None, profile)

    base_tokens = tokenize_inputs(name, pet, date, extras)

    # Build base variants for each token
    token_variants: Set[str] = set()
    for t in base_tokens:
        for cv in case_variants(t):
            capped_extend(token_variants, leet_variants(cv, mode=leet), cap=max_count)
            if len(token_variants) >= max_count:
                break
        if len(token_variants) >= max_count:
            break

    def within(s: str) -> bool:
        return minlen <= len(s) <= maxlen

    out: Set[str] = set()

    # 1) Single-token candidates
    for tv in token_variants:
        if within(tv):
            out.add(tv)
        if len(out) >= max_count:
            return sorted(out)

    # 2) Token + year with separators
    for tv in token_variants:
        for sep in separators:
            for y in years:
                candidate = f"{tv}{sep}{y}"
                if within(candidate):
                    out.add(candidate)
                    if len(out) >= max_count:
                        return sorted(out)

    # 3) Pairwise token combos with separators (controlled by profile)
    max_pairs = 20000 if profile == 'aggressive' else (8000 if profile == 'balanced' else 2000)
    count_pairs = 0
    tv_list = list(token_variants)
    for a, b in itertools.permutations(tv_list, 2):
        if a == b:
            continue
        for sep in separators:
            candidate = f"{a}{sep}{b}"
            if within(candidate):
                out.add(candidate)
                count_pairs += 1
                if len(out) >= max_count or count_pairs >= max_pairs:
                    return sorted(out)

    # 4) (Aggressive) Add year in the middle or suffix to pairwise
    if profile == 'aggressive':
        for a, b in itertools.permutations(tv_list, 2):
            for sep in separators:
                for y in years:
                    for fmt in (f"{a}{sep}{y}{sep}{b}", f"{a}{sep}{b}{sep}{y}"):
                        if within(fmt):
                            out.add(fmt)
                            if len(out) >= max_count:
                                return sorted(out)

    return sorted(out)


def save_wordlist(words: List[str], path: str):
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        for w in words:
            f.write(w + '\n')


# ---------------------------- CLI ---------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description='Password Strength Analyzer & Custom Wordlist Generator',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    p.add_argument('--password', '-p', required=True, help='Password to analyze')
    p.add_argument('--name', help='Name or full name (e.g., Lekhana)')
    p.add_argument('--pet', help='Pet name')
    p.add_argument('--date', help='Important date (YYYY, DDMMYYYY, YYYYMMDD, 2001-06-15, etc.)')
    p.add_argument('--extra', action='append', default=[], help='Extra clue(s), can repeat e.g. --extra college --extra company')

    p.add_argument('--profile', choices=['simple', 'balanced', 'aggressive'], default='balanced', help='Depth/size/profile for wordlist generation')
    p.add_argument('--leet', choices=['off', 'basic', 'extended'], default='basic', help='Leetspeak variant mode')
    p.add_argument('--append-years', help="Years to append, e.g., '1990-2028,2030'. Defaults depend on profile.")
    p.add_argument('--separators', help="Separators between tokens/years, e.g., '!,@,_,-'. Defaults depend on profile.")

    p.add_argument('--minlen', type=int, default=4, help='Minimum candidate length')
    p.add_argument('--maxlen', type=int, default=24, help='Maximum candidate length')
    p.add_argument('--max', dest='max_count', type=int, default=50000, help='Maximum number of candidates')

    p.add_argument('--outfile', '-o', default='wordlist.txt', help='Output .txt path for generated wordlist')
    p.add_argument('--no-wordlist', action='store_true', help='Analyze only, skip generation')

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Prepare settings
    years = parse_years_arg(args.append_years, args.profile)
    seps = [s for s in (args.separators.split(',') if args.separators else []) if s is not None]
    seps = seps or None  # allow profile defaults

    # Build user inputs for zxcvbn
    user_inputs = []
    user_inputs.extend([args.name or '', args.pet or '', args.date or ''])
    user_inputs.extend(args.extra)
    user_inputs = [u for u in user_inputs if u]

    # Analyze password
    analysis = analyze_password(args.password, user_inputs)

    print('\n=== Password Analysis ===')
    print(f"Backend     : {analysis['backend']}")
    print(f"Entropy bits: {analysis['entropy_bits']}")
    if analysis['score'] is not None:
        print(f"Score (0-4) : {analysis['score']}")
    if analysis['guesses'] is not None:
        print(f"Est. guesses: {analysis['guesses']}")
    if analysis['crack_times']:
        print('Crack times :', analysis['crack_times'])
    if analysis['feedback']:
        print('Feedback    :', '; '.join(analysis['feedback']))

    if args.no_wordlist:
        return

    # Leet setting
    leet_mode = 'off' if args.leet == 'off' else args.leet

    words = generate_wordlist(
        name=args.name,
        pet=args.pet,
        date=args.date,
        extras=args.extra,
        profile=args.profile,
        leet=leet_mode,
        append_years=years,
        separators=seps,
        minlen=args.minlen,
        maxlen=args.maxlen,
        max_count=args.max_count,
    )

    save_wordlist(words, args.outfile)

    print('\n=== Wordlist Generated ===')
    print(f"Profile     : {args.profile}")
    print(f"Candidates  : {len(words)}")
    print(f"Outfile     : {os.path.abspath(args.outfile)}")
    if len(words) > 0:
        print('Preview     :', ', '.join(words[:10]))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nInterrupted by user.', file=sys.stderr)
        sys.exit(1)
