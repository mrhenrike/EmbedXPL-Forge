"""
Crunch-style charset wordlist generator
# Original: https://github.com/derv82/werdy/blob/master/crunch.py
"""
import itertools, string, sys
from typing import Iterator

CHARSETS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()-_=+[]{}|;:,.<>?",
    "all": string.ascii_letters + string.digits + "!@#$%^&*",
}

def generate(charset: str = "lower+digits", min_len: int = 6, max_len: int = 8) -> Iterator[str]:
    chars = ""
    for part in charset.split("+"):
        chars += CHARSETS.get(part, part)
    chars = "".join(sorted(set(chars)))
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(chars, repeat=length):
            yield "".join(combo)

if __name__ == "__main__":
    charset = sys.argv[1] if len(sys.argv) > 1 else "lower+digits"
    min_l = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    max_l = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    for word in generate(charset, min_l, max_l):
        print(word)
