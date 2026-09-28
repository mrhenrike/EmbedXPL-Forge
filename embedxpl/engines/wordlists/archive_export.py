"""
archive_export.py - Exportação final de wordlists com sanitização e compressão.

Suporta: lst, txt (texto puro), tar, tar.gz, zip.
Temp files ficam em PROJECT_TMP (.tmp/ na raiz do projeto).

Author: André Henrique (@mrhenrike)
"""
from __future__ import annotations

import logging
import os
import shutil
import tarfile
import uuid
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from embedxpl.engines.wordlists.sanitizer import sanitize as _sanitize

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROJECT_TMP = PROJECT_ROOT / ".tmp"
PROJECT_TMP.mkdir(parents=True, exist_ok=True)

_SORT_MAP: dict[str, Optional[str]] = {
    "none": None,
    "alpha": "alpha",
    "alpha-desc": "alpha-rev",
    "length": "length",
    "length-desc": "length-rev",
}


class ExportFormat(str, Enum):
    """Supported wordlist export formats."""

    LST = "lst"
    TXT = "txt"
    TAR = "tar"
    TAR_GZ = "tar.gz"
    ZIP = "zip"


@dataclass
class ExportOptions:
    """Configuration for wordlist export pipeline.

    Attributes:
        format: Target file format.
        sanitize: Apply sanitization (dedup + strip control) before export.
        dedupe: Remove duplicate entries during sanitization.
        strip_control: Strip non-printable control characters.
        sort: Sort mode applied after sanitization.
        min_len: Minimum entry length filter (inclusive).
        max_len: Maximum entry length filter (inclusive).
        member_name: Filename used as the archive member inside tar/zip archives.
    """

    format: ExportFormat = ExportFormat.LST
    sanitize: bool = True
    dedupe: bool = True
    strip_control: bool = True
    sort: str = "none"
    min_len: Optional[int] = None
    max_len: Optional[int] = None
    member_name: str = "wordlist.lst"


def detect_format_from_path(path: str) -> ExportFormat:
    """Detect export format from the file path suffix.

    Args:
        path: Destination file path.

    Returns:
        Matching ExportFormat; defaults to LST when unrecognised.
    """
    lower = path.lower()
    if lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        return ExportFormat.TAR_GZ
    if lower.endswith(".tar"):
        return ExportFormat.TAR
    if lower.endswith(".zip"):
        return ExportFormat.ZIP
    if lower.endswith(".txt"):
        return ExportFormat.TXT
    return ExportFormat.LST


def export_wordlist(
    source_path: str,
    output_path: str,
    options: ExportOptions = ExportOptions(),
) -> dict:
    """Sanitise and export a wordlist to the specified format.

    Pipeline:
      1. Optionally sanitise into a temporary file under PROJECT_TMP.
      2. Copy/move the processed file to output_path for plain formats.
      3. Pack into a tar, tar.gz, or zip archive when requested.
      4. Clean the temporary file on success.

    Args:
        source_path: Path of the input wordlist.
        output_path: Destination path (format inferred from extension when not
            set in options, but ExportOptions.format takes precedence).
        options: Export configuration dataclass.

    Returns:
        Dict with keys: lines_in, lines_out, removed_dupes, format,
        output_path, size_bytes.

    Raises:
        FileNotFoundError: When source_path does not exist.
        ValueError: When options.sort contains an unsupported value.
    """
    src = Path(source_path)
    if not src.exists():
        raise FileNotFoundError(f"Source not found: {source_path}")

    if options.sort not in _SORT_MAP:
        raise ValueError(
            f"Unsupported sort value '{options.sort}'. "
            f"Choose from: {list(_SORT_MAP)}"
        )

    lines_in: int = 0
    lines_out: int = 0
    removed_dupes: int = 0

    tmp_file: Optional[Path] = None

    try:
        if options.sanitize:
            tmp_file = PROJECT_TMP / f"wfh_export_{uuid.uuid4().hex}.lst"
            sort_mode = _SORT_MAP[options.sort]
            stats = _sanitize(
                filepath=str(src),
                output=str(tmp_file),
                no_blank=True,
                no_comments=True,
                dedupe=options.dedupe,
                sort_mode=sort_mode,
                min_len=options.min_len,
                max_len=options.max_len,
                strip_control=options.strip_control,
            )
            lines_in = stats["total_input"]
            lines_out = stats["total_output"]
            removed_dupes = stats["removed_dupes"]
            work_file = tmp_file
        else:
            with src.open(encoding="utf-8", errors="replace") as fh:
                raw = [ln.rstrip("\n\r") for ln in fh if ln.strip()]
            lines_in = len(raw)
            lines_out = lines_in
            work_file = src

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        fmt = options.format

        if fmt in (ExportFormat.LST, ExportFormat.TXT):
            shutil.copy2(str(work_file), str(out))

        elif fmt == ExportFormat.TAR:
            with tarfile.open(str(out), "w") as tf:
                tf.add(str(work_file), arcname=options.member_name)

        elif fmt == ExportFormat.TAR_GZ:
            with tarfile.open(str(out), "w:gz") as tf:
                tf.add(str(work_file), arcname=options.member_name)

        elif fmt == ExportFormat.ZIP:
            with zipfile.ZipFile(
                str(out), "w", compression=zipfile.ZIP_DEFLATED
            ) as zf:
                zf.write(str(work_file), arcname=options.member_name)

        size_bytes = out.stat().st_size
        logger.info(
            "Exported %d lines to %s (%s, %d bytes)",
            lines_out,
            output_path,
            fmt.value,
            size_bytes,
        )

        return {
            "lines_in": lines_in,
            "lines_out": lines_out,
            "removed_dupes": removed_dupes,
            "format": fmt.value,
            "output_path": str(out),
            "size_bytes": size_bytes,
        }

    finally:
        if tmp_file is not None and tmp_file.exists():
            try:
                tmp_file.unlink()
            except OSError as exc:
                logger.warning("Could not remove temp file %s: %s", tmp_file, exc)


def ask_export_options(
    t_func=None,
    preset_path: str | None = None,
    ask_path: bool = True,
) -> tuple[ExportOptions, str]:
    """Prompt the user interactively for export options.

    Args:
        t_func: Optional i18n function t(key) → str. When None, English strings
            are used directly.
        preset_path: Output path already chosen (CLI/menu); skips path prompt.
        ask_path: When False, never prompt for output path.

    Returns:
        Tuple of (ExportOptions, output_path).
    """

    def _t(key: str, fallback: str) -> str:
        if t_func:
            text = t_func(key)
            return text if text != key else fallback
        return fallback

    sanitize_ans = input(
        f"  {_t('output.sanitize', 'Sanitize and remove duplicates? [Y/n]')}: "
    ).strip().lower()
    do_sanitize = sanitize_ans not in ("n", "no", "nao", "não")

    sort_choice = input(
        f"  {_t('output.sort', 'Sort? 0=keep order  1=alpha asc  2=alpha desc  3=length asc  4=length desc')}: "
    ).strip()
    sort_map_input: dict[str, str] = {
        "0": "none",
        "1": "alpha",
        "2": "alpha-desc",
        "3": "length",
        "4": "length-desc",
    }
    sort_mode = sort_map_input.get(sort_choice, "none")

    fmt_choice = input(
        f"  {_t('output.format', 'Format? 1=lst  2=txt  3=tar  4=tar.gz  5=zip')}: "
    ).strip()
    fmt_map: dict[str, ExportFormat] = {
        "1": ExportFormat.LST,
        "2": ExportFormat.TXT,
        "3": ExportFormat.TAR,
        "4": ExportFormat.TAR_GZ,
        "5": ExportFormat.ZIP,
    }
    export_fmt = fmt_map.get(fmt_choice, ExportFormat.LST)

    if ask_path and not preset_path:
        output_path = input(
            f"  {_t('output.path', 'Output file path (leave blank for default)')}: "
        ).strip()
    else:
        output_path = (preset_path or "").strip()

    opts = ExportOptions(
        format=export_fmt,
        sanitize=do_sanitize,
        dedupe=do_sanitize,
        strip_control=True,
        sort=sort_mode,
    )
    return opts, output_path
