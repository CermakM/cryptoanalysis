"""Test Vigener cipher algorithm"""

import os

from cipher.vigener import encode, decode
from common.util import match
from common.exception import ValueMismatch


VERBOSE = os.getenv('VERBOSE', 0)

TEST_SIMPLE_STR = "ineffable experience"
TEST_KEY = 'key'
TEST_CIPHERS = ["srcpjylpc obnovgorao", "tsdqkzmqd pcopwhpsbp"]


def test_encode_simple(rot=1, *args, **kwargs):
    """
    Test Vigener encoding
    :return: 0 on success
    """
    encoded_word = encode(stream=TEST_SIMPLE_STR, key=TEST_KEY, rot=0)

    if VERBOSE:
        print("Encoded string '{word}' using given key '{key}':\n\t{cipher}".format(
            word=TEST_SIMPLE_STR,
            key=TEST_KEY,
            cipher=encoded_word))

    return match(encoded_word, TEST_CIPHERS[rot])


def test_decode_simple(rot=1, *args, **kwargs):
    """
    Test Vigener decoding
    :return: 0 on success
    """

    test_cipher = TEST_CIPHERS[rot]

    decoded_word = decode(test_cipher, TEST_KEY, rot)

    if VERBOSE:
        print("Decoded string '{cipher}' using given key '{key}':\n\t{decoded}".format(
            cipher=test_cipher,
            key=TEST_KEY,
            decoded=decoded_word))

    return match(decoded_word, TEST_SIMPLE_STR)


if __name__ == '__main__':

    tests = [test_encode_simple, test_decode_simple]

    for test in tests:
        try:
            test(rot=0)
            result = '[PASSED]'
        except ValueMismatch as e:
            result = '[FAILED]\n\t' + str(e)

        print("{test} ... {result}".format(
            test=test.__name__,
            result=result
        ))
