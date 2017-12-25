"""
Python API for encoding and decoding a stream with a given key using Caesar cipher
Makes use of Vigener cipher - Caesar is just a simplification to key of lenght 1
"""

import cryptoanalysis.cipher.vigener as vigener


def encode(string: str, key: str) -> str:
    """
    Encode string using the Caesar cipher with the given key
    :param string: string to be encoded
    :param key: letter to be used as given shift
    :return: encoded string
    :raises: ValueError if key len is invalid
    """
    if len(key) > 1:
        raise ValueError("[ERROR] Length of a key may not exceed 1 for Caesar cipher")

    return vigener.encode(string, key)


def decode(cipher: str, key: str) -> str:
    """
    Decode string using the Caesar cipher with the given key
    :param cipher:  ciphered text stream to be decoded
    :param key: letter to be used as given shift
    :return: decoded string
    :raises: ValueError if key len is invalid
    """

    if len(key) > 1:
        raise ValueError("[ERROR] Length of a key may not exceed 1 for Caesar cipher")

    return vigener.decode(cipher, key)
