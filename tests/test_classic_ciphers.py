from defensive_python_labs.crypto.classic_ciphers import (
    caesar_decrypt,
    caesar_encrypt,
    vigenere_decrypt,
    vigenere_encrypt,
)


def test_caesar_roundtrip():
    plaintext = "HELLOWORLD"
    shift = 3
    ct = caesar_encrypt(plaintext, shift)
    pt = caesar_decrypt(ct, shift)
    assert pt == plaintext


def test_vigenere_roundtrip():
    plaintext = "ATTACKATDAWN"
    key = "LEMON"
    ct = vigenere_encrypt(plaintext, key)
    pt = vigenere_decrypt(ct, key)
    assert pt == plaintext
