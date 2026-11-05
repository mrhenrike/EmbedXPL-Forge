# Contributing to EmbedXPL-Forge

Thank you for your interest in contributing! This document explains the workflow for community contributions.

## Branch Naming Convention

All community contributions must use the `community/` prefix:

```
community/<your-username>-<short-description>
```

**Examples:**
- `community/mike3285-snmp-session-cleanup`
- `community/alice-add-roku-module`
- `community/bob-fix-upnp-ipv6`

Do **not** open PRs directly from your fork's `main` or `master` branch — they will be closed and you'll be asked to reopen from a named branch.

## Contribution Workflow

1. **Fork** the repository on GitHub
2. **Create a branch** in your fork:
   ```bash
   git checkout -b community/<your-username>-<description>
   ```
3. **Make your changes** — see the Code Style section below
4. **Run the quality gates** before opening a PR:
   ```bash
   python tools/run_scoped_tests.py      # syntax check (4 900+ files)
   ruff check .                          # linting
   python -m pytest tests/ --no-cov -q  # unit tests
   ```
5. **Open a Pull Request** targeting the `main` branch
6. **Fill in the PR template** — especially the Security checklist

## Code Style

- **Language:** all code, identifiers, comments, docstrings, and log messages must be in **English**
- **Formatter:** `ruff format` (line length 100)
- **Linter:** `ruff check` — zero warnings
- **Type hints:** required for all public functions and class attributes
- **No bare `except`:** always catch specific exception types
- **No `print()` in library code:** use `logging` instead

## What We Accept

- New exploit/scanner/autopwn modules for embedded devices
- Bug fixes and Python 3.12+ compatibility fixes
- New tests (we aim to increase coverage)
- Performance improvements
- Documentation improvements

## What We Do Not Accept (without prior discussion)

- Changes to the core exploit engine without an issue first
- Dependencies that require root/admin for `pip install`
- Modules that target non-embedded-device infrastructure (cloud, enterprise AD, etc.)
- Obfuscated code of any kind

## Review Process

All PRs are reviewed by `@mrhenrike` (the project owner). External PRs are automatically flagged for security review by our CI pipeline (`security-audit.yml`). The review includes:

- Automated bandit scan (high-severity findings block merge)
- Custom backdoor/C2/malicious-code scanner
- Semgrep `p/python` + `p/secrets` rule sets
- Manual code review

Expect a review within **3–5 business days** for small PRs, longer for large ones.

## Security Disclosure

If you find a security issue in EmbedXPL-Forge itself (not in target devices — that's the point), please open a **private security advisory** on GitHub rather than a public issue.

## License

By contributing, you agree that your contributions will be licensed under the same [BSD-3-Clause](LICENSE) license as the project.
