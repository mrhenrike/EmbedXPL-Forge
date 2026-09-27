"""
ocr_extractor.py - Extração de texto de imagens via OCR.

Usa easyocr como engine principal.
Aplica heurística para classificar tokens como usernames ou passwords.

Exemplos:
  wlf.py ocr imagem.png
  wlf.py ocr imagem.png --lang pt --out wordlist_ocr.txt

Autor: André Henrique (@mrhenrike)
Versão: 1.0.0
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import easyocr
    _EASYOCR_OK = True
except ImportError:
    _EASYOCR_OK = False
    logger.warning("easyocr não instalado. Instale com: pip install easyocr")

try:
    from PIL import Image
    _PIL_OK = True
except ImportError:
    _PIL_OK = False


# ── Heurística de classificação user/password ────────────────────────────────
# Padrões típicos de usernames
_USERNAME_PATTERNS = [
    re.compile(r"^[A-Z]{2}\d{4,8}$"),              # DS1206, IJ275601
    re.compile(r"^[a-z]+\d+@[a-z.]+$"),            # email corporativo
    re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"),  # email geral
    re.compile(r"^[A-Z]{4,6}\d{3,6}$"),            # DROGA1206
    re.compile(r"^\d{14}$"),                        # CNPJ como login
    re.compile(r"^[a-z]+\d{1,2}$"),                # mng1, mng2
]

# Padrões típicos de passwords
_PASSWORD_PATTERNS = [
    re.compile(r"^[a-zA-Z]+#\d+$"),                # Company#1206
    re.compile(r"^[a-zA-Z]+\d{4,}$"),              # company1206, brandx61585...
    re.compile(r".*[!@#$%&*_\-].*"),               # tem caractere especial
    re.compile(r"^[a-zA-Z0-9]{8,}$"),              # string alfanumérica longa
]

_MIN_TOKEN_LEN = 4
_MAX_TOKEN_LEN = 64


def _classify_token(token: str) -> str:
    """
    Classifica um token extraído como 'username', 'password' ou 'word'.

    Args:
        token: String a classificar.

    Returns:
        'username', 'password' ou 'word'.
    """
    for pat in _USERNAME_PATTERNS:
        if pat.match(token):
            return "username"
    for pat in _PASSWORD_PATTERNS:
        if pat.match(token):
            return "password"
    return "word"


def extract_from_image(
    image_path: str,
    lang: list[str] = ["pt", "en"],
    classify: bool = True,
) -> dict[str, list[str]]:
    """
    Extrai texto de uma imagem via OCR e classifica tokens.

    Args:
        image_path: Caminho para o arquivo de imagem.
        lang: Lista de idiomas para o OCR.
        classify: Se True, classifica tokens como user/password/word.

    Returns:
        Dict com chaves 'usernames', 'passwords', 'words'.

    Raises:
        FileNotFoundError: Se a imagem não existir.
        ImportError: Se easyocr não estiver instalado.
    """
    if not _EASYOCR_OK:
        raise ImportError("easyocr não instalado. Execute: pip install easyocr")

    path = Path(image_path)
    if not path.exists():
        raise FileNotFoundError(f"Imagem não encontrada: {image_path}")

    logger.info("Inicializando OCR (lang=%s)...", lang)
    reader = easyocr.Reader(lang, gpu=False)

    logger.info("Processando imagem: %s", image_path)
    results = reader.readtext(str(path))

    usernames: list[str] = []
    passwords: list[str] = []
    words: list[str] = []
    seen: set[str] = set()

    for _, text, confidence in results:
        if confidence < 0.3:
            continue

        # Dividir em tokens
        tokens = re.split(r"[\s|]+", text)
        for token in tokens:
            token = token.strip()
            if not token or len(token) < _MIN_TOKEN_LEN or len(token) > _MAX_TOKEN_LEN:
                continue
            if token in seen:
                continue
            seen.add(token)

            if classify:
                category = _classify_token(token)
                if category == "username":
                    usernames.append(token)
                elif category == "password":
                    passwords.append(token)
                else:
                    words.append(token)
            else:
                words.append(token)

    logger.info(
        "OCR concluído: %d usernames, %d passwords, %d words",
        len(usernames), len(passwords), len(words),
    )

    return {
        "usernames": usernames,
        "passwords": passwords,
        "words": words,
    }
