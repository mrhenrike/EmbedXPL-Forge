# Contributing to EmbedXPL-Forge

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)

Thank you for your interest in contributing to EmbedXPL-Forge!

## Important: Legal Notice

All contributions must be for **authorized security testing and research only**. Do not add modules that target systems without explicit permission. Any contribution implying unauthorized use will be rejected.

## How to Contribute

### Reporting bugs / requesting features

Open an [Issue](https://github.com/mrhenrike/EmbedXPL-Forge/issues) with:
- A clear title
- Steps to reproduce (for bugs)
- Expected vs. actual behavior
- Python version and OS

### Contributing a module

1. **Fork** the repository and create a branch: `feat/vendor-cve-XXXX`
2. **Add your module** in the correct category folder:
   - Routers: `embedxpl/modules/exploits/routers/<vendor>/`
   - Printers: `embedxpl/modules/exploits/printers/<vendor>/`
   - Firewalls: `embedxpl/modules/exploits/firewalls/<vendor>/`
   - ICS/OT: `embedxpl/modules/exploits/ics/`
   - Smart Home: `embedxpl/modules/exploits/smart_home/`
   - Embedded OS: `embedxpl/modules/exploits/embedded_os/`
   - Maritime/Specialized: `embedxpl/modules/exploits/specialized/`
3. **Follow the module template** (see below)
4. **Run quality gate**: `python tools/phase_gate.py --all` — must exit with code 0
5. **Run local checks**: `python tools/run_scoped_tests.py`
6. **Open a Pull Request** with CVE number, CVSS score, affected devices, and test evidence

### Module template

```python
"""One-line description of the vulnerability and exploit technique.

Full description explaining what the module does, affected device/versions,
and exploitation method. Reference the CVE and any relevant advisories.

References:
    https://nvd.nist.gov/vuln/detail/CVE-XXXX-YYYY
    https://www.exploit-db.com/exploits/NNNNN

Author: Your Name | Organization
"""

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Vendor Product - Vulnerability Type (CVE-XXXX-YYYY)",
        "description": (
            "One-line description of what this module does and how it exploits "
            "the vulnerability. Include affected versions and exploitation method."
        ),
        "authors": (
            "Your Name | Organization",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-XXXX-YYYY",
            "https://www.exploit-db.com/exploits/NNNNN",
        ),
        "devices": (
            "Vendor Model X",
            "Vendor Model Y (affected versions)",
        ),
        "cvss": "9.8",  # Required: CVSSv3 score or full vector string
    }

    target = OptIP("", "Target IPv4 address")
    port   = OptPort(80, "Target HTTP port")

    @mute
    def check(self) -> bool:
        # Real fingerprint of the target — detect if vulnerable
        resp = self.http_request(method="GET", path="/")
        if resp is None:
            return False
        body = (resp.text or "").lower()
        return "vendor_signature" in body

    def run(self) -> None:
        if not self.check():
            print_error("Target not applicable or not vulnerable")
            return
        # Exploitation logic here
        print_status("Exploiting CVE-XXXX-YYYY on {}:{}".format(self.target, self.port))
        # ... actual exploit code ...
        print_success("Exploitation successful")
```

### Quality gate requirements (checked automatically)

All modules must pass `python tools/phase_gate.py --all`:

- `class Exploit` present
- `__info__` with `name`, `description`, `authors`, `references` (URL), `devices`, `cvss`
- `check()` with real network fingerprint (not just `return True`)
- `run()` with real exploitation logic (not a stub)
- `check()` must return `False`/`None` on a closed port (anti-false-positive)
- No prohibited strings: em-dash (`--`), `TODO`, `PLACEHOLDER`, hardcoded lab IPs
- flake8 and bandit clean

### Code style

- Python 3.8+ compatible
- Type hints on public methods
- Google-style docstrings
- No `print()` — use `print_success()`, `print_error()`, `print_status()` from `embedxpl.core.exploit`
- No hardcoded credentials in module code (use wordlists)

## Development Setup

```bash
git clone https://github.com/mrhenrike/EmbedXPL-Forge.git
cd EmbedXPL-Forge
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
pip install ".[dev]"
```

## Running checks locally

```bash
# Full quality gate validation (required before PR)
python tools/phase_gate.py --all

# Scoped tests
python tools/run_scoped_tests.py

# Governance validation
python tools/validate_governance.py
python tools/validate_market_priority_minimums.py

# Linting
python -m flake8 tools exf.py --count --select=E9,F63,F7,F82
```

## License

By contributing, you agree that your contribution will be licensed under the [BSD License](LICENSE).

---

*[← Back to README](README.md)*
