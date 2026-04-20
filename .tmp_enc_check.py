import os, re

# 1. Check fake_dhcp_server for remaining issues
path = 'embedxpl/modules/exploits/ics/generic/fake_dhcp_server.py'
with open(path, encoding='utf-8') as fh:
    lines = fh.readlines()

print('=== fake_dhcp_server.py remaining issues ===')
found_any = False
for i, line in enumerate(lines, 1):
    stripped = line.strip()
    if re.search(r"f'[^']*\{", stripped) or re.search(r'f"[^"]*\{', stripped):
        print('  line {}: f-string: {}'.format(i, stripped[:80]))
        found_any = True
    try:
        stripped.encode('ascii')
    except UnicodeEncodeError:
        print('  line {}: non-ASCII: {}'.format(i, repr(stripped[:80])))
        found_any = True
if not found_any:
    print('  CLEAN')

# 2. Scan all modules for non-ASCII in print_* calls
print()
print('=== Non-ASCII in print_*/logger calls (encoding risk) ===')
risky = []
for root, dirs, files in os.walk('embedxpl'):
    dirs[:] = [d for d in dirs if d != '__pycache__']
    for f in files:
        if not f.endswith('.py') or f == '__init__.py':
            continue
        fpath = os.path.join(root, f)
        with open(fpath, encoding='utf-8') as fh:
            src_lines = fh.readlines()
        for i, line in enumerate(src_lines, 1):
            stripped = line.strip()
            if re.match(r'(print_|logger\.|print\()', stripped):
                try:
                    stripped.encode('ascii')
                except UnicodeEncodeError:
                    risky.append((fpath, i, stripped[:100]))

print('Count:', len(risky))
for p, i, code in risky[:30]:
    print('  {} line {}: {}'.format(p, i, repr(code)))
