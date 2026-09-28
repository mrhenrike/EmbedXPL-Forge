"""
file_extractor.py - Extração de conteúdo de múltiplos tipos de arquivo.

Suporta até 50 arquivos de entrada dos tipos:
  xlsx, xls, docx, doc, rtf, txt, md, py, c, rb,
  jpeg, jpg, bmp, tiff, png (via OCR), pdf

Exemplo:
  wlf.py extract arq1.pdf arq2.xlsx imagem.png -o wordlist_extraida.txt

Autor: André Henrique (@mrhenrike)
Versão: 1.0.0
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Generator, Optional

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
    Lê um arquivo de texto simples (txt, md, py, c, rb, etc.).

    Args:
        path: Caminho do arquivo.

    Returns:
        Conteúdo textual.
    """
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Erro ao ler %s: %s", path, exc)
        return ""


def _extract_xlsx(path: Path) -> str:
    """
    Extrai texto de todas as células de um XLSX.

    Args:
        path: Caminho do arquivo XLSX.

    Returns:
        Conteúdo concatenado das células.
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
        logger.warning("Erro ao ler XLSX %s: %s", path, exc)
        return ""


def _extract_docx(path: Path) -> str:
    """
    Extrai texto de um documento DOCX.

    Args:
        path: Caminho do arquivo DOCX.

    Returns:
        Texto extraído.
    """
    try:
        import docx
        doc = docx.Document(str(path))
        return "\n".join(p.text for p in doc.paragraphs)
    except Exception as exc:
        logger.warning("Erro ao ler DOCX %s: %s", path, exc)
        return ""


def _extract_rtf(path: Path) -> str:
    """
    Extrai texto de um arquivo RTF.

    Args:
        path: Caminho do arquivo RTF.

    Returns:
        Texto sem formatação RTF.
    """
    try:
        from striprtf.striprtf import rtf_to_text
        raw = path.read_bytes().decode("utf-8", errors="replace")
        return rtf_to_text(raw)
    except Exception as exc:
        logger.warning("Erro ao ler RTF %s: %s", path, exc)
        return ""


def _extract_pdf(path: Path) -> str:
    """
    Extrai texto de um PDF usando pdfplumber.

    Args:
        path: Caminho do arquivo PDF.

    Returns:
        Texto extraído de todas as páginas.
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
        logger.warning("Erro ao ler PDF %s: %s", path, exc)
        return ""


def _extract_image(path: Path) -> str:
    """
    Extrai texto de imagem via OCR (easyocr).

    Args:
        path: Caminho do arquivo de imagem.

    Returns:
        Texto extraído via OCR.
    """
    try:
        from .ocr_extractor import extract_from_image
        result = extract_from_image(str(path), classify=False)
        return " ".join(result.get("words", []) + result.get("usernames", []) + result.get("passwords", []))
    except Exception as exc:
        logger.warning("Erro ao processar imagem %s: %s", path, exc)
        return ""


def extract_from_file(path: Path) -> str:
    """
    Extrai texto de um arquivo baseado em sua extensão.

    Args:
        path: Caminho do arquivo.

    Returns:
        Texto extraído.
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
        logger.warning("Tipo de arquivo não suportado: %s", ext)
        return ""


def extract_wordlist_from_files(
    file_paths: list[str],
    min_len: int = _MIN_WORD_LEN,
    max_len: int = _MAX_WORD_LEN,
    dedup: bool = True,
) -> Generator[str, None, None]:
    """
    Extrai conteúdo de múltiplos arquivos e gera wordlist.

    Aceita até 50 arquivos. Suporta: xlsx, docx, rtf, txt, md,
    py, c, rb, jpeg, bmp, jpg, tiff, png (OCR), pdf.

    Args:
        file_paths: Lista de caminhos de arquivos (máximo 50).
        min_len: Comprimento mínimo dos tokens extraídos.
        max_len: Comprimento máximo dos tokens extraídos.
        dedup: Se True, remove duplicatas no output.

    Yields:
        Tokens únicos extraídos.
    """
    if len(file_paths) > _MAX_FILES:
        logger.warning(
            "Máximo de %d arquivos permitidos. Usando apenas os primeiros %d.",
            _MAX_FILES, _MAX_FILES,
        )
        file_paths = file_paths[:_MAX_FILES]

    seen: set[str] = set()

    for filepath in file_paths:
        path = Path(filepath)
        if not path.exists():
            logger.warning("Arquivo não encontrado: %s", filepath)
            continue

        logger.info("Extraindo: %s", filepath)
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
