"""
Educational hash cracker — dictionary and brute-force attack demo.

PURPOSE: Understand WHY weak passwords and unsalted hashes are dangerous.
Do NOT use this against hashes you do not own.

Supports: MD5, SHA1, SHA256, SHA512, bcrypt (if installed)
"""

from __future__ import annotations

import hashlib
import itertools
import string
import time
from dataclasses import dataclass
from typing import Iterator, List, Optional

SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]


@dataclass
class CrackResult:
    found: bool
    plaintext: Optional[str]
    algorithm: str
    attempts: int
    elapsed_seconds: float

    def __str__(self) -> str:
        status = f"✓ CRACKED: '{self.plaintext}'" if self.found else "✗ Not found in wordlist"
        return (
            f"Algorithm : {self.algorithm.upper()}\n"
            f"Result    : {status}\n"
            f"Attempts  : {self.attempts:,}\n"
            f"Time      : {self.elapsed_seconds:.3f}s"
        )


def _hash(text: str, algorithm: str) -> str:
    """Compute a hex digest using the given algorithm."""
    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def identify_hash(hash_str: str) -> List[str]:
    """
    Guess possible hash algorithms based on hash length.

    Parameters
    ----------
    hash_str : str
        Hexadecimal hash string.

    Returns
    -------
    List[str]
        Candidate algorithm names.

    Examples
    --------
    >>> identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    ['md5']
    >>> identify_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    ['sha1']
    """
    length_map = {
        32: ["md5"],
        40: ["sha1"],
        64: ["sha256"],
        128: ["sha512"],
    }
    return length_map.get(len(hash_str.strip()), ["unknown"])


def dictionary_attack(
    target_hash: str,
    algorithm: str,
    wordlist: List[str],
    use_common_mutations: bool = True,
) -> CrackResult:
    """
    Try to crack a hash using a dictionary wordlist.

    Optionally applies common mutations (append digits, capitalize, leet-speak).

    Parameters
    ----------
    target_hash : str
        Hash to crack (hex string).
    algorithm : str
        Hash algorithm: 'md5', 'sha1', 'sha256', 'sha512'.
    wordlist : List[str]
        List of candidate plaintext strings.
    use_common_mutations : bool
        If True, also try password1, Password, p@ssword variants.

    Returns
    -------
    CrackResult
        Whether cracked, the plaintext if found, and stats.

    Examples
    --------
    >>> import hashlib
    >>> h = hashlib.md5(b"hello").hexdigest()
    >>> result = dictionary_attack(h, "md5", ["world", "hello", "test"])
    >>> result.found
    True
    >>> result.plaintext
    'hello'
    """
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from {SUPPORTED_ALGORITHMS}")

    target = target_hash.lower().strip()
    attempts = 0
    start = time.perf_counter()

    def _candidates(word: str) -> Iterator[str]:
        yield word
        if use_common_mutations:
            yield word.capitalize()
            yield word.upper()
            for suffix in ["1", "123", "!", "2024", "2023", "2025"]:
                yield word + suffix
                yield word.capitalize() + suffix
            # Basic leet speak
            yield word.replace("a", "@").replace("e", "3").replace("o", "0").replace("i", "1")

    for word in wordlist:
        for candidate in _candidates(word):
            attempts += 1
            if _hash(candidate, algorithm) == target:
                elapsed = time.perf_counter() - start
                return CrackResult(
                    found=True,
                    plaintext=candidate,
                    algorithm=algorithm,
                    attempts=attempts,
                    elapsed_seconds=elapsed,
                )

    elapsed = time.perf_counter() - start
    return CrackResult(
        found=False,
        plaintext=None,
        algorithm=algorithm,
        attempts=attempts,
        elapsed_seconds=elapsed,
    )


def brute_force(
    target_hash: str,
    algorithm: str,
    charset: str = string.ascii_lowercase + string.digits,
    max_length: int = 5,
) -> CrackResult:
    """
    Brute-force a hash by trying all combinations up to max_length.

    WARNING: Exponential complexity. Only practical for very short passwords.
    This function exists to DEMONSTRATE why short passwords are broken instantly.

    Parameters
    ----------
    target_hash : str
        Hash to crack.
    algorithm : str
        Hash algorithm.
    charset : str
        Characters to use (default: lowercase + digits).
    max_length : int
        Maximum candidate length to try (default 5 — already takes seconds).

    Examples
    --------
    >>> import hashlib
    >>> h = hashlib.md5(b"abc").hexdigest()
    >>> result = brute_force(h, "md5", max_length=3)
    >>> result.found
    True
    """
    target = target_hash.lower().strip()
    attempts = 0
    start = time.perf_counter()

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1
            if _hash(candidate, algorithm) == target:
                elapsed = time.perf_counter() - start
                return CrackResult(
                    found=True,
                    plaintext=candidate,
                    algorithm=algorithm,
                    attempts=attempts,
                    elapsed_seconds=elapsed,
                )

    elapsed = time.perf_counter() - start
    return CrackResult(
        found=False,
        plaintext=None,
        algorithm=algorithm,
        attempts=attempts,
        elapsed_seconds=elapsed,
    )
