"""
poly_runner — Orquestrador multi-linguagem para execução de exploits em
qualquer linguagem (Python, C/C++, Ruby/Metasploit, Node.js, Go, Rust, PHP, Perl).

Suporta compilação (C/C++/Go/Rust) e execução de runtimes externos
(Ruby/MSF, Node, PHP, Perl, PowerShell).

Todos os builds usam .tmp/build/ do projeto (nunca diretórios externos).

Funções públicas principais:
  detect(lang)            → caminho do compilador/runtime ou None
  detect_msf()            → caminho do msfconsole ou None
  available_langs()       → dict {lang: path_or_None} para todas as linguagens
  build(src, lang, ...)   → compila source → binário em .tmp/build/
  run(src, lang, ...)     → detect + build (se compilado) + executa + retorna dict
  run_msf(module, ...)    → gera RC script + msfconsole -r → retorna dict
  run_from_dir(dir, ...)  → auto-detecta source no diretório + despacha para run()

# Autor: André Henrique (@mrhenrike) | União Geek
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

# ── Build directory inside the project workspace ──────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.parent.parent
_BUILD_TMP = _PROJECT_ROOT / ".tmp" / "build"

# ── Compiler/runtime detection tables ─────────────────────────────────────────
_COMPILERS: dict[str, list[str]] = {
    "c":    ["gcc", "clang", "cc"],
    "cpp":  ["g++", "clang++", "c++"],
    "go":   ["go"],
    "rust": ["cargo"],
}

_RUNTIMES: dict[str, list[str]] = {
    "ruby":       ["ruby"],
    "node":       ["node", "nodejs"],
    "php":        ["php"],
    "perl":       ["perl"],
    "powershell": ["pwsh", "powershell"],
    "python":     [sys.executable],
    "sh":         ["sh", "bash"],
}

_MSF_BINARIES = ["msfconsole", "msfexec"]

# WSL binary (Windows only) — used as fallback compiler/runtime host
_WSL_BIN: Optional[str] = shutil.which("wsl") if sys.platform == "win32" else None


# ── Source file extension → language key ──────────────────────────────────────
_EXT_TO_LANG: dict[str, str] = {
    ".c":   "c",
    ".cpp": "cpp",
    ".cc":  "cpp",
    ".go":  "go",
    ".rs":  "rust",
    ".rb":  "ruby",
    ".js":  "node",
    ".php": "php",
    ".pl":  "perl",
    ".ps1": "powershell",
    ".sh":  "sh",
    ".py":  "python",
}

# Source file names considered as exploit entry points when auto-discovering
_SOURCE_CANDIDATES = ["source.c", "source.cpp", "exploit.c", "exploit.cpp",
                      "exploit.rb", "exploit.go", "exploit.rs",
                      "exploit.js", "exploit.php", "exploit.pl", "exploit.ps1"]


# ── Public API ─────────────────────────────────────────────────────────────────

def detect(lang: str) -> Optional[str]:
    """Return path to first available compiler/runtime for *lang*, or None.

    On Windows, if no native compiler is found for C/C++/Go/Rust, falls back
    to checking inside WSL via ``wsl <compiler> --version``.  When the WSL
    fallback succeeds, returns the string ``"wsl:<compiler>"`` as a sentinel
    that ``build()`` and ``run()`` recognise and dispatch via ``wsl``.
    """
    lang = lang.lower()
    candidates: list[str] = []
    if lang in _COMPILERS:
        candidates = _COMPILERS[lang]
    elif lang in _RUNTIMES:
        candidates = _RUNTIMES[lang]
    else:
        return None

    for name in candidates:
        found = shutil.which(name)
        if found:
            return found

    # WSL fallback on Windows for compiled languages
    if sys.platform == "win32" and _WSL_BIN and lang in _COMPILERS:
        wsl_compiler = _COMPILERS[lang][0]  # e.g. "gcc"
        probe = subprocess.run(
            [_WSL_BIN, wsl_compiler, "--version"],
            capture_output=True, text=True,
        )
        if probe.returncode == 0:
            return f"wsl:{wsl_compiler}"

    return None


def detect_msf() -> Optional[str]:
    """Return path to msfconsole binary, or None if Metasploit is not installed."""
    for name in _MSF_BINARIES:
        found = shutil.which(name)
        if found:
            return found
    return None


def available_langs() -> dict[str, Optional[str]]:
    """Return a mapping of every supported language to its detected binary path.

    Keys include all compiler languages (c, cpp, go, rust) and all runtime
    languages (ruby, node, php, perl, powershell, python, sh).  The value is
    the resolved binary path or ``None`` when not installed.

    Useful for ``--xpl-list`` output to flag exploits with unmet dependencies
    and for the exploit_manager dependency check.

    Returns:
        dict: ``{"c": "/usr/bin/gcc", "ruby": None, ...}``
    """
    result: dict[str, Optional[str]] = {}
    for lang in list(_COMPILERS) + list(_RUNTIMES):
        result[lang] = detect(lang)
    return result


def run_from_dir(
    module_dir: Path,
    host: str,
    port: int,
    timeout: float = 30.0,
    dry_run: bool = False,
    extra_args: Optional[list[str]] = None,
    build_flags: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Auto-detect a non-Python source file in *module_dir* and execute it.

    Searches for candidate source files in *module_dir* following the priority
    order defined in ``_SOURCE_CANDIDATES``.  The first match determines the
    language and is passed to :func:`run`.

    This helper lets ``exploit.py`` wrappers delegate execution to poly_runner
    without needing to know the exact source filename or language key::

        from src.core import poly_runner
        from pathlib import Path

        _DIR = Path(__file__).parent

        def run(host, port=9100, timeout=15, dry_run=True, **opts):
            return poly_runner.run_from_dir(_DIR, host, port,
                                             timeout=timeout, dry_run=dry_run)

    Parameters
    ----------
    module_dir  : Directory that contains the source file (usually the same
                  directory as the calling ``exploit.py``).
    host        : Target host.
    port        : Target port.
    timeout     : Execution timeout in seconds.
    dry_run     : If True, return metadata without executing.
    extra_args  : Extra CLI arguments forwarded to the exploit binary/script.
    build_flags : Compiler flags forwarded to :func:`build` (compiled langs).

    Returns
    -------
    dict with keys: success, vulnerable, output, evidence, error, lang, runner.
    Returns an error dict when no source file is found.
    """
    module_dir = Path(module_dir)

    for candidate in _SOURCE_CANDIDATES:
        src = module_dir / candidate
        if src.exists():
            lang = _EXT_TO_LANG.get(src.suffix.lower(), "")
            if not lang:
                return _error_result("unknown",
                                     f"run_from_dir: unsupported extension '{src.suffix}'")
            artifact = module_dir.name or src.stem
            return run(
                src=src,
                lang=lang,
                host=host,
                port=port,
                timeout=timeout,
                dry_run=dry_run,
                extra_args=extra_args,
                build_flags=build_flags,
                artifact_name=artifact,
            )

    return _error_result(
        "unknown",
        f"run_from_dir: no supported source file found in '{module_dir}' "
        f"(searched: {_SOURCE_CANDIDATES})",
    )


def build(
    src: Path,
    lang: str,
    artifact_name: str,
    build_flags: Optional[list[str]] = None,
) -> Path:
    """
    Compile *src* → .tmp/build/<artifact_name>/exploit (or .exe on Windows).

    Uses a **compilation cache**: if the binary already exists and its
    modification time is newer than *src*, the existing binary is returned
    immediately without recompiling.

    Parameters
    ----------
    src           : Path to source file (.c, .cpp, .go, etc.)
    lang          : Language key — "c", "cpp", "go", "rust"
    artifact_name : Directory name under .tmp/build/ for isolation
    build_flags   : Extra compiler flags (e.g. ["-lpthread"])

    Returns
    -------
    Path to the compiled binary.

    Raises
    ------
    RuntimeError  : If compiler not found or compilation fails.
    """
    lang = lang.lower()
    if lang not in _COMPILERS:
        raise RuntimeError(f"poly_runner: no compiler registered for lang='{lang}'")

    compiler = detect(lang)
    if not compiler:
        raise RuntimeError(
            f"poly_runner: no compiler found for lang='{lang}' "
            f"(tried: {_COMPILERS[lang]})"
        )

    out_dir = _BUILD_TMP / artifact_name
    out_dir.mkdir(parents=True, exist_ok=True)

    binary_name = "exploit.exe" if sys.platform == "win32" else "exploit"
    binary_path = out_dir / binary_name
    flags = build_flags or []

    # Compilation cache: skip rebuild if binary is newer than source
    if binary_path.exists() and src.exists():
        if binary_path.stat().st_mtime >= src.stat().st_mtime:
            return binary_path

    # Detect WSL-based compilation (compiler path starts with "wsl:")
    using_wsl = compiler.startswith("wsl:")
    wsl_compiler = compiler.split(":", 1)[1] if using_wsl else compiler

    if using_wsl:
        # Convert Windows path to WSL Linux path (/mnt/X/ convention)
        def _win_to_wsl(p: Path) -> str:
            import re as _re
            s = str(p.resolve())  # always absolute before converting
            m = _re.match(r'^([A-Za-z]):[/\\](.*)', s)
            if m:
                drive = m.group(1).lower()
                rest  = m.group(2).replace("\\", "/")
                return f"/mnt/{drive}/{rest}"
            return s.replace("\\", "/")

        wsl_src  = _win_to_wsl(src)
        wsl_out  = _win_to_wsl(binary_path)

        if lang == "go":
            cmd = [_WSL_BIN, wsl_compiler, "build", "-o", wsl_out, wsl_src]  # type: ignore[list-item]
        elif lang == "rust":
            cmd = [_WSL_BIN, "rustc", wsl_src, "-o", wsl_out] + flags  # type: ignore[list-item]
        else:
            cmd = [_WSL_BIN, wsl_compiler, wsl_src, "-o", wsl_out] + flags  # type: ignore[list-item]
    elif lang == "go":
        cmd = [compiler, "build", "-o", str(binary_path), str(src)]
    elif lang == "rust":
        rustc = shutil.which("rustc")
        if not rustc:
            raise RuntimeError("poly_runner: rustc not found")
        cmd = [rustc, str(src), "-o", str(binary_path)] + flags
    else:
        # C / C++
        cmd = [compiler, str(src), "-o", str(binary_path)] + flags

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(out_dir),
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"poly_runner: compilation failed ({compiler}):\n"
            f"  STDOUT: {result.stdout}\n"
            f"  STDERR: {result.stderr}"
        )

    return binary_path


def run(
    src: Path,
    lang: str,
    host: str,
    port: int,
    timeout: float = 30.0,
    dry_run: bool = False,
    extra_args: Optional[list[str]] = None,
    build_flags: Optional[list[str]] = None,
    artifact_name: Optional[str] = None,
) -> dict[str, Any]:
    """
    Full pipeline: detect → build (if compiled) → execute → parse → return result.

    For compiled languages (C/C++/Go/Rust), the source is compiled first via
    `build()`, then the binary is executed with `host port [extra_args]`.

    For interpreted languages (Python/Ruby/Node/PHP/Perl), the runtime is
    invoked directly: `runtime src host port [extra_args]`.

    Parameters
    ----------
    src           : Path to source or script file
    lang          : Language key
    host          : Target host
    port          : Target port
    timeout       : Execution timeout in seconds
    dry_run       : If True, skip actual execution and return metadata only
    extra_args    : Additional CLI arguments passed to the exploit
    build_flags   : Compiler flags (compiled langs only)
    artifact_name : Override build dir name (defaults to src.stem)

    Returns
    -------
    dict with keys: success, vulnerable, output, evidence, error, lang, runner
    """
    lang = lang.lower()
    extra_args = extra_args or []
    artifact = artifact_name or src.stem

    if dry_run:
        return {
            "success": True,
            "vulnerable": None,
            "output": f"[DRY-RUN] poly_runner: would execute {lang} exploit {src.name} against {host}:{port}",
            "evidence": "",
            "error": "",
            "lang": lang,
            "runner": "poly_runner",
            "dry_run": True,
        }

    try:
        if lang in _COMPILERS:
            binary = build(src, lang, artifact, build_flags)
            # If compiled via WSL, the binary is an ELF — run it via wsl
            if _WSL_BIN and sys.platform == "win32":
                probe = subprocess.run(
                    ["file", str(binary)] if shutil.which("file") else
                    [_WSL_BIN, "file", _win_to_wsl_safe(binary)],
                    capture_output=True, text=True,
                )
                is_elf = "ELF" in probe.stdout
            else:
                is_elf = False

            if is_elf and _WSL_BIN:
                wsl_bin_path = _win_to_wsl_safe(binary)
                cmd = [_WSL_BIN, wsl_bin_path, host, str(port)] + extra_args
            else:
                cmd = [str(binary), host, str(port)] + extra_args
        elif lang in _RUNTIMES:
            runtime = detect(lang)
            if not runtime:
                return _error_result(lang, f"runtime not found for '{lang}'")
            cmd = [runtime, str(src), host, str(port)] + extra_args
        else:
            return _error_result(lang, f"unknown language '{lang}'")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return _normalize(result.stdout, result.stderr, result.returncode, lang)

    except subprocess.TimeoutExpired:
        return _error_result(lang, f"timeout after {timeout}s")
    except RuntimeError as exc:
        return _error_result(lang, str(exc))
    except Exception as exc:
        return _error_result(lang, f"unexpected error: {exc}")
    finally:
        _cleanup_build(artifact)


def run_msf(
    msf_module: str,
    host: str,
    port: int,
    payload: Optional[str] = None,
    lhost: Optional[str] = None,
    lport: Optional[int] = None,
    extra_options: Optional[dict[str, str]] = None,
    timeout: float = 120.0,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Execute a Metasploit module via msfconsole -q -r <rc_script>.

    Parameters
    ----------
    msf_module    : MSF module path (e.g. "exploit/windows/local/cve_2020_1048_printerdemon")
    host          : RHOST value
    port          : RPORT value
    payload       : Optional payload string
    lhost         : LHOST for reverse shells
    lport         : LPORT for reverse shells
    extra_options : Dict of additional MSF options
    timeout       : Execution timeout in seconds
    dry_run       : If True, return script without executing

    Returns
    -------
    dict with keys: success, vulnerable, output, evidence, error, lang, runner
    """
    msf_bin = detect_msf()

    # Build resource script
    rc_lines = [
        f"use {msf_module}",
        f"set RHOSTS {host}",
        f"set RPORT {port}",
    ]
    if payload:
        rc_lines.append(f"set PAYLOAD {payload}")
    if lhost:
        rc_lines.append(f"set LHOST {lhost}")
    if lport:
        rc_lines.append(f"set LPORT {lport}")
    for k, v in (extra_options or {}).items():
        rc_lines.append(f"set {k} {v}")
    rc_lines.extend(["run", "exit"])
    rc_content = "\n".join(rc_lines)

    if dry_run or not msf_bin:
        reason = "DRY-RUN" if dry_run else "msfconsole not found"
        return {
            "success": True if dry_run else False,
            "vulnerable": None,
            "output": f"[{reason}] MSF RC script:\n{rc_content}",
            "evidence": "",
            "error": "" if dry_run else "Metasploit not installed",
            "lang": "ruby",
            "runner": "poly_runner_msf",
            "dry_run": dry_run,
            "msf_module": msf_module,
        }

    # Write RC script to project .tmp (never system /tmp)
    rc_path = _BUILD_TMP / f"msf_{int(time.time())}.rc"
    rc_path.parent.mkdir(parents=True, exist_ok=True)
    rc_path.write_text(rc_content, encoding="utf-8")

    try:
        result = subprocess.run(
            [msf_bin, "-q", "-r", str(rc_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return _normalize_msf(result.stdout, result.stderr, result.returncode)
    except subprocess.TimeoutExpired:
        return _error_result("ruby", f"msfconsole timeout after {timeout}s")
    except Exception as exc:
        return _error_result("ruby", f"msfconsole error: {exc}")
    finally:
        if rc_path.exists():
            rc_path.unlink(missing_ok=True)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _win_to_wsl_safe(p: Path) -> str:
    """Convert a Windows path to a WSL Linux path string (best-effort).

    Converts ``D:\\foo\\bar`` → ``/mnt/d/foo/bar`` using the standard WSL
    drive-mount convention.  Falls back to a forward-slash replacement when
    the path does not match a Windows drive letter pattern.
    """
    s = str(p)
    # Windows absolute path: e.g. D:\foo\bar  or  d:/foo/bar
    import re as _re
    m = _re.match(r'^([A-Za-z]):[/\\](.*)', s)
    if m:
        drive  = m.group(1).lower()
        rest   = m.group(2).replace("\\", "/")
        return f"/mnt/{drive}/{rest}"
    # Already a WSL/POSIX path or relative
    return s.replace("\\", "/")


def _normalize(stdout: str, stderr: str, rc: int, lang: str) -> dict[str, Any]:
    success = rc == 0
    vulnerable = success and bool(stdout.strip())
    evidence = stdout
    if stderr and rc != 0:
        evidence += f"\n[STDERR]: {stderr}"
    return {
        "success": success,
        "vulnerable": vulnerable,
        "output": stdout,
        "evidence": evidence,
        "error": stderr if rc != 0 else "",
        "returncode": rc,
        "lang": lang,
        "runner": "poly_runner",
    }


def _normalize_msf(stdout: str, stderr: str, rc: int) -> dict[str, Any]:
    """Parse msfconsole output for session/success indicators."""
    lines = stdout.lower()
    session_opened = bool(re.search(r"session \d+ opened", lines))
    exploited = bool(re.search(r"\[\+\]", stdout))
    failed = bool(re.search(r"\[-\].*exploit failed|no session", lines))
    vulnerable = session_opened or exploited
    return {
        "success": rc == 0 and not failed,
        "vulnerable": vulnerable,
        "output": stdout,
        "evidence": stdout if vulnerable else "",
        "error": stderr if rc != 0 else "",
        "returncode": rc,
        "lang": "ruby",
        "runner": "poly_runner_msf",
        "session_opened": session_opened,
    }


def _error_result(lang: str, msg: str) -> dict[str, Any]:
    return {
        "success": False,
        "vulnerable": False,
        "output": "",
        "evidence": "",
        "error": msg,
        "lang": lang,
        "runner": "poly_runner",
    }


def _cleanup_build(artifact_name: str) -> None:
    """Remove compiled artifacts from .tmp/build/<artifact_name>/."""
    build_dir = _BUILD_TMP / artifact_name
    if build_dir.exists():
        shutil.rmtree(build_dir, ignore_errors=True)
