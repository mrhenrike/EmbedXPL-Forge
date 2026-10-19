
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

_cached_os = None


def get_os() -> str:
    """
    Detect the host operating system.

    Returns one of:
        'linux'    – Standard Linux
        'wsl'      – Windows Subsystem for Linux
        'android'  – Android via Termux (or similar)
        'windows'  – Native Windows
        'darwin'   – macOS
        'bsd'      – FreeBSD / OpenBSD / NetBSD
        'unsupported' – anything else

    Result is cached after the first call.
    """
    global _cached_os
    if _cached_os:
        return _cached_os

    import platform
    import os

    sysname = platform.system().lower()

    if "linux" in sysname:
        # ── Android / Termux detection ──────────────────────────────────
        # Android uses a Linux kernel but has a distinct runtime environment.
        # Termux sets TERMUX_VERSION env var; alternatively check for /data/data.
        if (
            os.environ.get("TERMUX_VERSION")
            or os.path.isdir("/data/data/com.termux")
            or os.environ.get("PREFIX", "").startswith("/data/data/com.termux")
        ):
            _cached_os = "android"
            return _cached_os

        # ── WSL detection ────────────────────────────────────────────────
        osrelease = '/proc/sys/kernel/osrelease'
        if os.path.exists(osrelease):
            try:
                with open(osrelease) as f:
                    content = f.read().lower()
                    if 'microsoft' in content or 'wsl' in content:
                        _cached_os = "wsl"
                        return _cached_os
            except OSError:
                pass

        _cached_os = "linux"
        return _cached_os

    if "windows" in sysname:
        _cached_os = "windows"
        return _cached_os

    if "darwin" in sysname:
        _cached_os = "darwin"  # macOS
        return _cached_os

    if any(bsd in sysname for bsd in ("freebsd", "openbsd", "netbsd")):
        _cached_os = "bsd"
        return _cached_os

    _cached_os = "unsupported"
    return _cached_os
