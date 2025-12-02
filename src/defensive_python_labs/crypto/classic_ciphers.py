"""Simple classic cipher implementations for educational purposes.

These algorithms are **not** secure and must not be used for real security.
"""

from __future__ import annotations

from string import ascii_uppercase


_ALPHABET = ascii_uppercase


def _normalize_text(text: str) -> str:
    """Uppercase letters and strip non-letters for simple demos."""
    return "".join(ch for ch in text.upper() if ch in _ALPHABET)


def caesar_encrypt(plaintext: str, shift: int) -> str:
    """Encrypt text using a Caesar shift.

    Examples
    --------
    >>> caesar_encrypt("ABC", 1)
    'BCD'
    """
    pt = _normalize_text(plaintext)
    result_chars: list[str] = []
    for ch in pt:
        idx = _ALPHABET.index(ch)
        result_chars.append(_ALPHABET[(idx + shift) % len(_ALPHABET)])
    return "".join(result_chars)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt a Caesar shift by applying the negative shift."""
    return caesar_encrypt(ciphertext, -shift)


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Encrypt text with the Vigenère cipher.

    The key is repeated or truncated to match the plaintext length.
    """
    pt = _normalize_text(plaintext)
    key_norm = _normalize_text(key)
    if not key_norm:
        raise ValueError("Key must contain at least one alphabetic character.")

    result_chars: list[str] = []
    for i, ch in enumerate(pt):
        key_ch = key_norm[i % len(key_norm)]
        p_idx = _ALPHABET.index(ch)
        k_idx = _ALPHABET.index(key_ch)
        result_chars.append(_ALPHABET[(p_idx + k_idx) % len(_ALPHABET)])
    return "".join(result_chars)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt Vigenère by subtracting the key shift."""
    ct = _normalize_text(ciphertext)
    key_norm = _normalize_text(key)
    if not key_norm:
        raise ValueError("Key must contain at least one alphabetic character.")

    result_chars: list[str] = []
    for i, ch in enumerate(ct):
        key_ch = key_norm[i % len(key_norm)]
        c_idx = _ALPHABET.index(ch)
        k_idx = _ALPHABET.index(key_ch)
        result_chars.append(_ALPHABET[(c_idx - k_idx) % len(_ALPHABET)])
    return "".join(result_chars)
