# Contributing to RouterXPL-Forge

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)

Thank you for your interest in contributing to RouterXPL-Forge!

## Important: Legal Notice

All contributions must be for **authorized security testing and research only**. Do not add modules that target systems without explicit permission. Any contribution implying unauthorized use will be rejected.

## How to Contribute

### Reporting bugs / requesting features

Open an [Issue](https://github.com/mrhenrike/RouterXPL-Forge/issues) with:
- A clear title
- Steps to reproduce (for bugs)
- Expected vs. actual behavior
- Python version and OS

### Contributing a module

1. **Fork** the repository and create a branch: `feat/vendor-cve-XXXX`
2. **Add your module** in the correct vendor folder under `routerxpl/modules/exploits/routers/<vendor>/`
3. **Follow the module template** (see below)
4. **Run local checks**: `python tools/run_scoped_tests.py`
5. **Open a Pull Request** with a description of the CVE, affected devices, and test evidence

### Module template

```python
"""<Short description of the exploit>.

Author: Your Name | Organization
"""

from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient

__info__ = {
    "name": "Vendor Product — Vulnerability Type",
    "description": "One-line description of what this module does.",
    "authors": ("Your Name",),
    "references": (
        "https://nvd.nist.gov/vuln/detail/CVE-XXXX-YYYY",
    ),
    "devices": (
        "Vendor Model X",
    ),
}


class Exploit(HTTPClient):
    target = OptIP("", "Target IPv4 address")
    port   = OptPort(80, "Target HTTP port")

    def run(self) -> None:
        # Your exploit logic here
        pass

    def check(self) -> bool:
        # Optional pre-validation
        return False
```

### Code style

- Python 3.8+ compatible
- Type hints on public methods
- Google-style docstrings
- No `print()` — use `print_success()`, `print_error()`, `print_status()` from `routerxpl.core.exploit`
- No hardcoded credentials in module code (use wordlists)

## Development Setup

```bash
git clone https://github.com/mrhenrike/RouterXPL-Forge.git
cd RouterXPL-Forge
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
pip install ".[dev]"
```

## Running checks locally

```bash
python tools/run_scoped_tests.py
python tools/validate_governance.py
python tools/validate_market_priority_minimums.py
python -m flake8 tools rxf.py --count --select=E9,F63,F7,F82
```

## License

By contributing, you agree that your contribution will be licensed under the [BSD License](LICENSE).

---

*[← Back to README](README.md)*
