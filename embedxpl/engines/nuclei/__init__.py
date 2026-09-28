"""EmbedXPL Nuclei engine — nuclei-templates scanner integration.

nuclei-templates are stored at:
  /run/media/mrhenrike/Data/Projects/Submodulos/Hacking/nuclei-templates/

Usage:
    from embedxpl.engines.nuclei import get_templates_path, run_nuclei
    
    # Get path to all templates
    path = get_templates_path()
    
    # Run nuclei against target
    result = run_nuclei("192.168.1.1", tags=["router", "cve"], severity=["critical", "high"])

# authorized use only
"""
from __future__ import annotations
import os, subprocess, shutil
from pathlib import Path

_TEMPLATES_DEFAULT = Path(
    "/run/media/mrhenrike/Data/Projects/Submodulos/Hacking/nuclei-templates"
)

def get_templates_path() -> Path:
    env = os.environ.get("NUCLEI_TEMPLATES_PATH", "")
    if env and Path(env).exists():
        return Path(env)
    return _TEMPLATES_DEFAULT

def run_nuclei(
    target: str,
    templates: str | None = None,
    tags: list[str] | None = None,
    severity: list[str] | None = None,
    timeout: int = 120,
) -> dict:
    """Run nuclei scanner against target."""
    nuclei_bin = shutil.which("nuclei")
    if not nuclei_bin:
        return {"error": "nuclei not installed (apt install nuclei)", "returncode": -1}
    
    tpath = templates or str(get_templates_path())
    cmd = [nuclei_bin, "-target", target, "-templates", tpath, "-silent", "-json"]
    if tags:
        cmd += ["-tags", ",".join(tags)]
    if severity:
        cmd += ["-severity", ",".join(severity)]
    
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"returncode": r.returncode, "stdout": r.stdout, "stderr": r.stderr[:500]}
    except subprocess.TimeoutExpired:
        return {"error": f"Timeout after {timeout}s", "returncode": -1}
    except Exception as e:
        return {"error": str(e), "returncode": -1}
