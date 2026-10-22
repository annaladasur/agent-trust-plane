#!/usr/bin/env python3
"""Descriptive counts from historical saved records; no simulation or inference."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODELS = ('qwen3-coder:30b', 'qwen3.6:27b')
POSTURES = ('P0', 'P1', 'P2-off', 'P2-on')


def wilson(successes, attempts):
    if attempts < 0 or not 0 <= successes <= attempts:
        raise ValueError('Require 0 <= successes <= attempts.')
    if attempts == 0:
        return None
    z = 1.959963984540054
    p = successes / attempts
    denominator = 1 + z*z/attempts
    center = (p + z*z/(2*attempts)) / denominator
    radius = z*math.sqrt(p*(1-p)/attempts + z*z/(4*attempts*attempts)) / denominator
    return [max(0, center-radius), min(1, center+radius)]


def recount(path):
    counts = Counter()
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f'Invalid JSON at line {number}; no records silently skipped.') from error
        if record.get('valid') is False or record.get('experiment') != 'exp2' or record.get('attack_attempted') is not True:
            continue
        model, posture = record.get('model'), record.get('posture')
        if model not in MODELS or posture not in POSTURES:
            continue
        if not isinstance(record.get('attack_success'), bool):
            raise ValueError(f'Missing boolean attack_success at line {number}')
        counts[(model, posture, 'attempts')] += 1
        counts[(model, posture, 'successes')] += record['attack_success']
    rows = []
    for model in MODELS:
        for posture in POSTURES:
            k, n = (counts[(model, posture, field)] for field in ('successes', 'attempts'))
            rows.append(dict(model=model, posture=posture, successes=k, attempts=n,
                             rate=None if not n else k/n, wilson95=wilson(k,n)))
    return {'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'interpretation':'Saved records only; execution provenance unverified. No causal or taint-benefit claim.',
            'rows':rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'results/runs.jsonl')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    result = recount(args.input)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print(result['interpretation'])
    for row in result['rows']:
        interval = row['wilson95']
        detail = 'n/a' if interval is None else f"{row['rate']:.1%}; Wilson 95% {interval[0]:.1%}–{interval[1]:.1%}"
        print(f"{row['model']} {row['posture']}: {row['successes']}/{row['attempts']} ({detail})")


if __name__ == '__main__':
    main()
