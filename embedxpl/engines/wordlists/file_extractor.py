"""
file_extractor.py - Content extraction from multiple file types.

Supports up to 50 input files of types:
  xlsx, xls, docx, doc, rtf, txt, md, py, c, rb,
  jpeg, jpg, bmp, tiff, png (via OCR), pdf

Example:
  wlf.py extract file1.pdf file2.xlsx image.png -o extracted_wordlist.txt

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

_MAX_FILES = 50
_MIN_WORD_LEN = 4
_MAX_WORD_LEN = 64

_WORD_RE = re.compile(r"[a-zA-ZÀ-ÿ\u0100-\u024F0-9@#$\-_!.]{4,64}")

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".tif", ".gif"}
TEXT_EXTS = {".txt", ".md", ".py", ".c", ".rb", ".csv", ".log", ".json", ".yaml", ".yml"}
OFFICE_EXTS = {".xlsx", ".xls", ".xlsm"}
WORD_EXTS = {".docx"}
RTF_EXTS = {".rtf"}
PDF_EXTS = {".pdf"}


def _extract_text_file(path: Path) -> str:
    """
    Read a plain text file (txt, md, py, c, rb, etc.).

    Args:
        path: File path.

    Returns:
        Text content.
    """
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Error reading %s: %s", path, exc)
        return ""


def _extract_xlsx(path: Path) -> str:
    """
    Extract text from all cells of an XLSX file.

    Args:
        path: XLSX file path.

    Returns:
        Concatenated cell content.
    """
    try:
        import openpyxl
        wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
        parts: list[str] = []
        for ws in wb.worksheets:
            for row in ws.iter_rows(values_only=True):
                for cell in row:
                    if cell is not None:
                        parts.append(str(cell))
        wb.close()
        return " ".join(parts)
    except Exception as exc:
        logger.warning("Error reading XLSX %s: %s", path, exc)
        return ""


def _extract_docx(path: Path) -> str:
    """
    Extract text from a DOCX document.

    Args:
        path: DOCX file path.

    Returns:
        Extracted text.
    """
    try:
        import docx
        doc = docx.Document(str(path))
        return "\n".join(p.text for p in doc.paragraphs)
    except Exception as exc:
        logger.warning("Error reading DOCX %s: %s", path, exc)
        return ""


def _extract_rtf(path: Path) -> str:
    """
    Extract text from an RTF file.

    Args:
        path: RTF file path.

    Returns:
        Plain text without RTF formatting.
    """
    try:
        from striprtf.striprtf import rtf_to_text
        raw = path.read_bytes().decode("utf-8", errors="replace")
        return rtf_to_text(raw)
    except Exception as exc:
        logger.warning("Error reading RTF %s: %s", path, exc)
        return ""


def _extract_pdf(path: Path) -> str:
    """
    Extract text from a PDF using pdfplumber.

    Args:
        path: PDF file path.

    Returns:
        Text extracted from all pages.
    """
    try:
        import pdfplumber
        parts: list[str] = []
        with pdfplumber.open(str(path)) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    parts.append(text)
        return "\n".join(parts)
    except Exception as exc:
        logger.warning("Error reading PDF %s: %s", path, exc)
        return ""


def _extract_image(path: Path) -> str:
    """
    Extract text from an image via OCR (easyocr).

    Args:
        path: Image file path.

    Returns:
        Text extracted via OCR.
    """
    try:
        from .ocr_extractor import extract_from_image
        result = extract_from_image(str(path), classify=False)
        return " ".join(result.get("words", []) + result.get("usernames", []) + result.get("passwords", []))
    except Exception as exc:
        logger.warning("Error processing image %s: %s", path, exc)
        return ""


def extract_from_file(path: Path) -> str:
    """
    Extract text from a file based on its extension.

    Args:
        path: File path.

    Returns:
        Extracted text.
    """
    ext = path.suffix.lower()

    if ext in TEXT_EXTS:
        return _extract_text_file(path)
    elif ext in OFFICE_EXTS:
        return _extract_xlsx(path)
    elif ext in WORD_EXTS:
        return _extract_docx(path)
    elif ext in RTF_EXTS:
        return _extract_rtf(path)
    elif ext in PDF_EXTS:
        return _extract_pdf(path)
    elif ext in IMAGE_EXTS:
        return _extract_image(path)
    else:
        logger.warning("Unsupported file type: %s", ext)
        return ""


def extract_wordlist_from_files(
    file_paths: list[str],
    min_len: int = _MIN_WORD_LEN,
    max_len: int = _MAX_WORD_LEN,
    dedup: bool = True,
) -> Generator[str, None, None]:
    """
    Extract content from multiple files and generate a wordlist.

    Accepts up to 50 files. Supports: xlsx, docx, rtf, txt, md,
    py, c, rb, jpeg, bmp, jpg, tiff, png (OCR), pdf.

    Args:
        file_paths: List of file paths (maximum 50).
        min_len: Minimum length of extracted tokens.
        max_len: Maximum length of extracted tokens.
        dedup: If True, deduplicate the output.

    Yields:
        Unique extracted tokens.
    """
    if len(file_paths) > _MAX_FILES:
        logger.warning(
            "Maximum %d files allowed. Using only the first %d.",
            _MAX_FILES, _MAX_FILES,
        )
        file_paths = file_paths[:_MAX_FILES]

    seen: set[str] = set()

    for filepath in file_paths:
        path = Path(filepath)
        if not path.exists():
            logger.warning("File not found: %s", filepath)
            continue

        logger.info("Extracting: %s", filepath)
        text = extract_from_file(path)

        for match in _WORD_RE.finditer(text):
            token = match.group().strip(".,;:!?\"'")
            if min_len <= len(token) <= max_len:
                if dedup:
                    if token not in seen:
                        seen.add(token)
                        yield token
                else:
                    yield token
