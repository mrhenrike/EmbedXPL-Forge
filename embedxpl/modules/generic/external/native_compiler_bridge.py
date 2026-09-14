"""Native Compiler Bridge for EmbedXPL.

Provides compile_and_run() for C/Ruby/Bash source files embedded in
embedxpl/resources/native_src/. Always compiles to workspace-local .tmp/
directory — never uses OS /tmp per workspace operational guardrails.

Original code
-------------
Author: Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

_WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
_NATIVE_SRC     = _WORKSPACE_ROOT / "embedxpl" / "resources" / "native_src"
_BUILD_TMP      = _WORKSPACE_ROOT / ".tmp" / "native_builds"

_BUILD_TMP.mkdir(parents=True, exist_ok=True)


def _resolve_src(lang: str, relative_path: str) -> Optional[Path]:
    """Resolve a path relative to native_src/<lang>/."""
    candidates = [
        _NATIVE_SRC / lang / relative_path,
        _NATIVE_SRC / relative_path,
        Path(relative_path),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def compile_and_run(
    lang: str,
    src_path: str,
    args: list[str] | None = None,
    timeout: int = 60,
    compiler: str = "auto",
    env: dict | None = None,
) -> dict[str, Any]:
    """Compile (if needed) and run a native source file.

    Parameters
    ----------
    lang     : 'c', 'ruby', 'bash', 'python', 'js'
    src_path : path relative to native_src/<lang>/ or absolute
    args     : additional CLI arguments
    timeout  : execution timeout in seconds
    compiler : 'auto' | 'gcc' | 'clang' | 'g++'
    env      : extra environment variables

    Returns
    -------
    dict with keys: returncode, stdout, stderr, error
    """
    result: dict[str, Any] = {"returncode": -1, "stdout": "", "stderr": "", "error": ""}
    src = _resolve_src(lang, src_path)
    if src is None:
        result["error"] = f"Source not found: native_src/{lang}/{src_path}"
        return result

    run_env = os.environ.copy()
    if env:
        run_env.update(env)

    if lang == "c":
        cc = (
            shutil.which(compiler) if compiler != "auto"
            else (shutil.which("gcc") or shutil.which("clang") or shutil.which("cc"))
        )
        if not cc:
            result["error"] = "C compiler not found (gcc/clang/cc)"
            return result
        binary = _BUILD_TMP / f"{src.stem}_embed_build"
        try:
            cp = subprocess.run(
                [cc, str(src), "-o", str(binary), "-lm"],
                capture_output=True, text=True, timeout=120, env=run_env,
            )
            if cp.returncode != 0:
                result["error"] = f"Compile: {cp.stderr[:300]}"
                return result
        except Exception as exc:
            result["error"] = str(exc)
            return result
        try:
            proc = subprocess.run(
                [str(binary)] + (args or []),
                capture_output=True, text=True, timeout=timeout, env=run_env,
            )
            result.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        except subprocess.TimeoutExpired:
            result["error"] = f"Timeout after {timeout}s"
        except Exception as exc:
            result["error"] = str(exc)
        finally:
            binary.unlink(missing_ok=True)

    elif lang == "ruby":
        interp = shutil.which("ruby")
        if not interp:
            result["error"] = "ruby not found"
            return result
        try:
            proc = subprocess.run(
                [interp, str(src)] + (args or []),
                capture_output=True, text=True, timeout=timeout, env=run_env,
            )
            result.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        except subprocess.TimeoutExpired:
            result["error"] = f"Timeout after {timeout}s"
        except Exception as exc:
            result["error"] = str(exc)

    elif lang in ("bash", "sh"):
        sh = shutil.which("bash") or shutil.which("sh")
        if not sh:
            result["error"] = "bash/sh not found"
            return result
        try:
            proc = subprocess.run(
                [sh, str(src)] + (args or []),
                capture_output=True, text=True, timeout=timeout,
                cwd=str(_BUILD_TMP), env=run_env,
            )
            result.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        except subprocess.TimeoutExpired:
            result["error"] = f"Timeout after {timeout}s"
        except Exception as exc:
            result["error"] = str(exc)

    elif lang in ("python", "py"):
        try:
            proc = subprocess.run(
                [sys.executable, str(src)] + (args or []),
                capture_output=True, text=True, timeout=timeout, env=run_env,
            )
            result.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        except subprocess.TimeoutExpired:
            result["error"] = f"Timeout after {timeout}s"
        except Exception as exc:
            result["error"] = str(exc)

    elif lang in ("js", "node"):
        node = shutil.which("node") or shutil.which("nodejs")
        if not node:
            result["error"] = "node/nodejs not found"
            return result
        try:
            proc = subprocess.run(
                [node, str(src)] + (args or []),
                capture_output=True, text=True, timeout=timeout, env=run_env,
            )
            result.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        except subprocess.TimeoutExpired:
            result["error"] = f"Timeout after {timeout}s"
        except Exception as exc:
            result["error"] = str(exc)

    else:
        result["error"] = f"Unknown language: {lang}"

    return result


def available_sources() -> dict[str, list[str]]:
    """List all available native source files by language."""
    catalog: dict[str, list[str]] = {}
    if not _NATIVE_SRC.exists():
        return catalog
    for lang_dir in _NATIVE_SRC.iterdir():
        if lang_dir.is_dir():
            files = [str(f.relative_to(_NATIVE_SRC / lang_dir.name))
                     for f in lang_dir.rglob("*")
                     if f.is_file() and not f.name.startswith(".")]
            if files:
                catalog[lang_dir.name] = sorted(files)
    return catalog
