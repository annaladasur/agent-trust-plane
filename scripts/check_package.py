#!/usr/bin/env python3
"""Check the standalone package for missing local links and forbidden artifacts."""
from pathlib import Path
import ast
import re
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
problems=[]
for path in ROOT.rglob('*'):
    rel=path.relative_to(ROOT)
    if '.git' in rel.parts or '__pycache__' in rel.parts or not path.is_file():
        continue
    if path.suffix in ('.key','.pem','.env') or path.name == '.gitea.env':
        problems.append(f'Forbidden credential artifact: {rel}')
    if path.suffix=='.py':
        ast.parse(path.read_text(), filename=str(rel))
    if path.suffix=='.md':
        for link in re.findall(r'\]\(([^)]+)\)', path.read_text()):
            if link.startswith(('http:','https:','mailto:','#')):
                continue
            local=unquote(link.split('#')[0])
            if local and not (path.parent/local).exists():
                problems.append(f'{rel}: missing link {local}')
    if path.suffix in ('.py','.yaml','.yml','.json','.jsonl','.md','.sh'):
        text=path.read_text()
        if re.search(r'-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}',text):
            problems.append(f'Potential non-fixture credential: {rel}')
if problems:
    raise SystemExit('\n'.join(problems))
print('Standalone links, Python syntax and credential-artifact checks passed.')
