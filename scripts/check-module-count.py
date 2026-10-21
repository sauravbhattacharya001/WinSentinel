#!/usr/bin/env python3
"""Module-count consistency check.

The audit-module count has ONE source of truth: the code in
src/WinSentinel.Core/Audits (one *Audit.cs class per module, each registered
in AuditEngine). Every published claim — README.md and
docfx/articles/audit-modules.md — must match it. When a module is added or
removed, this check fails until the docs are updated, so the count can never
silently drift again.

Run: python3 scripts/check-module-count.py   (exit 1 on any mismatch)
"""
import glob
import re
import sys

failures = []

# --- truth: the code ---
files = [f for f in glob.glob('src/WinSentinel.Core/Audits/*Audit.cs')]
engine = open('src/WinSentinel.Core/Services/AuditEngine.cs').read()
registered = set(re.findall(r'new\s+(\w+Audit)\s*\(', engine))
on_disk = {f.split('/')[-1][:-3] for f in files}
count = len(on_disk)
if on_disk != registered:
    failures.append(
        f'AuditEngine registers {len(registered)} modules but {count} '
        f'*Audit.cs files exist (unregistered: {sorted(on_disk - registered)}, '
        f'missing files: {sorted(registered - on_disk)})')

def check_claims(path, text):
    # Bare "N modules" claims count too (diagram labels, tree comments) --
    # the "13 modules" architecture-diagram fossil hid behind the missing
    # word "audit" until 2026-10-21.
    for pat in (r'(\d+)\s+audit modules', r'(\d+)\s+Audit Modules',
                r'(?<!audit )(\d+)\s+modules\b'):
        for m in re.finditer(pat, text, re.IGNORECASE):
            if int(m.group(1)) != count:
                failures.append(f'{path}: claims {m.group(1)} audit modules, code has {count}')

# --- README.md ---
readme = open('README.md').read()
check_claims('README.md', readme)
m = re.search(r'Modules scanned:\s*(\d+)', readme)
if m and int(m.group(1)) != count:
    failures.append(f'README.md: sample output says "Modules scanned: {m.group(1)}", code has {count}')
lines = readme.splitlines()
hdr = next(i for i, l in enumerate(lines) if l.startswith('| # | Module |'))
rows = 0
for l in lines[hdr + 2:]:
    if l.startswith('|'):
        rows += 1
    else:
        break
if rows != count:
    failures.append(f'README.md: Audit Modules table has {rows} rows, code has {count}')

# --- docfx/articles/audit-modules.md ---
doc = open('docfx/articles/audit-modules.md').read()
check_claims('docfx/articles/audit-modules.md', doc)
dl = doc.splitlines()
ov = next(i for i, l in enumerate(dl) if l.startswith('## Module Overview'))
hdr = next(i for i in range(ov, len(dl)) if dl[i].startswith('| Module |'))
rows = 0
for l in dl[hdr + 2:]:
    if l.startswith('|'):
        rows += 1
    else:
        break
if rows != count:
    failures.append(f'docfx audit-modules.md: overview table has {rows} rows, code has {count}')
non_module = {'Module Overview', 'Severity Levels', 'Creating Custom Modules'}
sections = {l[3:].strip() for l in dl if l.startswith('## ')} - non_module
if len(sections) != count:
    failures.append(f'docfx audit-modules.md: {len(sections)} module sections, code has {count}')

if failures:
    print(f'MODULE COUNT CHECK FAILED (code count: {count})')
    for f in failures:
        print(' -', f)
    sys.exit(1)
print(f'module count OK: {count} modules, all published claims match the code')
