#!/usr/bin/env python3
"""Evaluate the real Rego policies against local, synthetic JSON examples."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def evaluate(opa, fixture, query):
    executable = shutil.which(opa)
    if not executable:
        raise RuntimeError('OPA is required. Install the official OPA release and add it to PATH.')
    run = subprocess.run([executable, 'eval', '--format=json', '--data', str(ROOT / 'policies'),
                          '--input', str(fixture), query], capture_output=True, text=True, check=True)
    data = json.loads(run.stdout)
    try:
        return data['result'][0]['expressions'][0]['value']
    except (KeyError, IndexError, TypeError) as error:
        raise RuntimeError('Policy returned no decision; refusing to treat undefined as allowed.') from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--opa', default='opa', help='OPA executable name or path')
    args = parser.parse_args()
    cases = json.loads((ROOT / 'examples/cases.json').read_text())
    print('Synthetic inputs; actual OPA policy evaluation. No model or external tool is called.')
    for case in cases:
        actual = evaluate(args.opa, ROOT / 'examples' / case['file'], case['query'])
        if actual != case['expected']:
            raise RuntimeError(f"{case['name']}: expected {case['expected']!r}, received {actual!r}")
        print(f"PASS {case['name']}: {actual}")
    print(f'{len(cases)} policy examples passed.')


if __name__ == '__main__':
    main()
