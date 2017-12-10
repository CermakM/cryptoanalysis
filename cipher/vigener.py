"""Python API for encoding and decoding a stream with a given key using Vigener cipher"""

# Set up default blacklist for Vigener cipher - characters not to be encoded
DEFAULT_BLACKLIST = [chr(ascii) for ascii in range(32, 65)] + [chr(ascii) for ascii in range(91, 97)] + ['\n']


def strip_blacklist(stream: str, blacklist: list = None) -> tuple:
    """
    Strip stream, get rid of characters given by blacklist
    :param stream: text stream
    :param blacklist: list of characters to strip
    :return: tuple, (stream, dict{index : char})
    """

    if blacklist is None:
        blacklist = DEFAULT_BLACKLIST

    # Convert list for constant access
    blacklist_dict = dict((b, 1) for b in blacklist)

    _stream = ""
    _blacklisted_chars = {}
    "dictionary {index: char}"

    for index, c in enumerate(stream):
        if c in blacklist_dict:
            _blacklisted_chars[index] = c
        else:
            _stream += c

    return _stream, _blacklisted_chars


def destrip_blacklist(stream: str, feed_dict: dict) -> str:
    """
    Reverse strip operation
    :param stream:
    :param feed_dict:
    :return: destripped stream
    """

    if not feed_dict:
        from sys import stderr
        print("vigener.destrip_blacklist: [WARNING]: empty feed_dict provided - stripping will not be performed",
              file=stderr)

        return stream

    _stream = ""
    offset = 0
    for i, w in enumerate(stream):
        if i + offset in feed_dict:
            _stream += feed_dict[i + offset]
            offset += 1

        _stream += w

    return _stream


def encode(stream: str, key: str, blacklist: list = None, rot: int = 1) -> str:
    """
    Encode string using the Vigener cipher with the given key
    :param stream: string to be encoded
    :param key: string to be used as given pwd
    :param rot: 'a' transforms to 'a' for 0, to 'b' for 1 (default)
    :param blacklist: list of characters to strip
    :return: encoded string
    """

    # convert to lowercase
    stream, key = stream.lower(), key.lower()

    # Get rid of blacklisted charactes and store them in dictionary by index key
    stream, blacklist_dict = strip_blacklist(stream, blacklist)

    # crop the key
    key_stream = "".join(key[i % len(key)] for i, _ in enumerate(stream))

    encoded_stream = ""
    for k, w in zip(key_stream, stream):
        # convert to ordinals
        k_ord = ord(k) - ord('a') + rot  # get the shift value
        w_ord = ord(w)

        # Encode values and convert back to character
        encoded_stream += chr([k_ord + w_ord, k_ord + w_ord - 26][k_ord + w_ord > ord('z')])

    encoded_stream = destrip_blacklist(encoded_stream, blacklist_dict)

    return encoded_stream


def decode(cipher: str, key: str, rot: int = 1, strip=True) -> str:
    """
    Decode string using the Vigener cipher with the given key
    :param cipher:  ciphered text stream to be decoded
    :param key: string to be used as given pwd
    :param rot: 'a' transforms to 'a' for 0, to 'b' for 1 (default)
    :param strip: perform strip, bool (True default)
    :return: decoded string
    """
    encoded_stream, blacklist_dict = cipher, {}
    if strip:
        encoded_stream, blacklist_dict = strip_blacklist(cipher)

    # crop the key
    key_stream = "".join(key[i % len(key)] for i, _ in enumerate(cipher))

    decoded_cipher = ""
    for k, w in zip(key_stream, encoded_stream):

        # convert to ordinals
        k = ord(k) - ord('a') + rot  # get the shift value
        w = ord(w)

        # Encode values and convert back to character
        decoded_cipher += chr([w - k, w - k + 26][w - k < ord('a')])

    decoded_cipher = destrip_blacklist(decoded_cipher, feed_dict=blacklist_dict)

    return decoded_cipher
