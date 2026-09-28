"""
xor_crypto.py - Ferramenta XOR de criptografia e brute-force de chave.

Port Python 3 do decriptorxor.py original (Python 2).
Funcionalidades:
  - Criptografia XOR com chave arbitrária
  - Descriptografia XOR com chave conhecida
  - Brute-force de chave XOR de 1 byte (256 tentativas)
  - Scoring de texto legível para identificar resultado correto

Uso:
  wlf.py xor --brute HEXSTRING
  wlf.py xor --encrypt "texto" --key "chave"
  wlf.py xor --decrypt HEXSTRING --key "chave"

Autor: André Henrique (@mrhenrike)
Versão: 1.0.0
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Charset de texto legível para scoring
_READABLE_CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    ".,\"-+_?/'\n !@#$%&*()[]{}:;<>"
)


def score_text(text: str) -> int:
    """
    Calcula score de legibilidade de um texto.

    Quanto maior o score, mais legível é o texto (mais chars do charset).

    Args:
        text: String a avaliar.

    Returns:
        Número de caracteres legíveis no texto.
    """
    return sum(1 for ch in text if ch in _READABLE_CHARSET)


def xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Descriptografa bytes com chave XOR (repeating key).

    Args:
        ciphertext: Bytes cifrados.
        key: Chave XOR (pode ser de qualquer comprimento).

    Returns:
        Bytes descriptografados.
    """
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(ciphertext))


def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Criptografa bytes com chave XOR (repeating key).

    Args:
        plaintext: Bytes em texto plano.
        key: Chave XOR (pode ser de qualquer comprimento).

    Returns:
        Bytes cifrados.
    """
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(plaintext))


def xor_encrypt_str(plaintext: str, key: str, encoding: str = "utf-8") -> bytes:
    """
    Criptografa string com chave XOR.

    Args:
        plaintext: Texto em claro.
        key: Chave como string.
        encoding: Encoding para conversão.

    Returns:
        Bytes cifrados.
    """
    return xor_encrypt(plaintext.encode(encoding), key.encode(encoding))


def xor_decrypt_str(ciphertext: bytes, key: str, encoding: str = "utf-8") -> str:
    """
    Descriptografa bytes com chave XOR e retorna string.

    Args:
        ciphertext: Bytes cifrados.
        key: Chave como string.
        encoding: Encoding para decodificação do resultado.

    Returns:
        Texto descriptografado (erros substituídos).
    """
    decrypted = xor_decrypt(ciphertext, key.encode(encoding))
    return decrypted.decode(encoding, errors="replace")


def brute_force_single_byte(hex_string: str) -> list[dict]:
    """
    Brute-force de chave XOR de 1 byte sobre dados hexadecimais.

    Testa todos os 256 valores possíveis de chave de 1 byte e
    ranqueia os resultados por score de legibilidade.

    Args:
        hex_string: String hexadecimal dos dados cifrados (ex: "1a2b3c4d").

    Returns:
        Lista de dicts com 'key', 'key_char', 'score', 'result',
        ordenada por score decrescente. Inclui apenas top 10.
    """
    try:
        data = bytes.fromhex(hex_string.strip())
    except ValueError as exc:
        logger.error("Hex inválido: %s", exc)
        return []

    candidates: list[dict] = []

    for key_byte in range(256):
        key = bytes([key_byte])
        decrypted = xor_decrypt(data, key)
        try:
            text = decrypted.decode("utf-8", errors="replace")
        except Exception:
            text = decrypted.decode("latin-1", errors="replace")

        s = score_text(text)
        candidates.append({
            "key": key_byte,
            "key_char": chr(key_byte) if 32 <= key_byte < 127 else f"0x{key_byte:02X}",
            "score": s,
            "result": text,
        })

    candidates.sort(key=lambda x: x["score"], reverse=True)
    return candidates[:10]


def brute_force_display(hex_string: str) -> None:
    """
    Executa brute-force e exibe os melhores resultados no terminal.

    Args:
        hex_string: String hexadecimal dos dados cifrados.
    """
    results = brute_force_single_byte(hex_string)
    if not results:
        print("Nenhum resultado. Verifique o hex fornecido.")
        return

    print(f"\n=== XOR Brute-Force - Top {len(results)} resultados ===\n")
    for i, r in enumerate(results, 1):
        print(f"#{i:2d}  Key=0x{r['key']:02X} ({r['key_char']!r:5s})  Score={r['score']:4d}  Result: {r['result'][:80]!r}")
