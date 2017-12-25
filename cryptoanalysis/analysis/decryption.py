"""Decryption tools"""

import numpy as np
import pandas as pd

from collections import Counter, deque
from matplotlib import pyplot as plt
from cryptoanalysis.cipher import vigener

import cryptoanalysis

META_DIR = "%s/meta" % cryptoanalysis.__path__[0]


class Analyser:

    def __init__(self, cipher: str = None, fname: str = None, cipher_type='mono', lang='en'):
        """
        Analyser class providing tools to analyse and decrypt ciphers
        :param cipher: encoded stream to be decrypted
        :param fname: file to read string from
        :param cipher_type: mono alphabetic by default
        :param lang: language to choose
        """
        if fname and cipher:
            raise ValueError("Only one argument can be provided at time: `cipher`, `file`")

        if fname is not None:
            with open(fname) as sample:
                cipher = sample.read()

        self.cipher = cipher

        if cipher:
            self.cipher_strip, self.blacklist_dict = vigener.strip_blacklist(cipher.lower())

        self.type = cipher_type
        self.lang = lang

        # Convenient dictionary to store per-key shift vectors
        self.shift_dict = dict()

        _lang_df = pd.read_csv('{meta_dir}/{lang}.csv'.format(meta_dir=META_DIR, lang=self.lang))

        self.alphabet = _lang_df.letters.values
        self.letter_frequency = _lang_df.occurence.values
        "DataFrame with cipher character frequency"

        self.default_alphabet_dct = dict(zip(self.alphabet, (0 for _ in range(len(self.alphabet)))))

    def get_cipher(self) -> str:
        """Returns ciphered text"""
        return self.cipher

    def get_char_occurance(self):
        """Returns bag of character occurence count"""
        return Counter(self.cipher_strip)

    def get_char_frequency(self) -> dict:
        """Returns dictionary of characters and their occurence"""
        series = pd.Series(Counter(self.cipher_strip))
        series /= series.sum()

        return series.to_dict()

    def get_shift_vector(self, key_index) -> list:
        """Returns shift vector for key character on specific index"""
        if not self.shift_dict:
            return []

        return self.shift_dict[key_index]

    def plot_char_frequency(self):
        """Plot frequency analysis using pandas DataFrame"""
        bag = Counter(self.default_alphabet_dct)
        bag.update(self.cipher_strip)

        cipher_frequency = self.__df_from_dict(bag)
        "DataFrame with cipher character frequency"
        ax = cipher_frequency.plot(
            title='Frequency analysis of the given cipher',
            kind='bar',
            rot=0  # Prevent letters from rotating by 90 deg
        )
        ax.legend(['Character count'])
        plt.show()

    def decipher(self, custom_key=None, key_id=0, rot=0) -> str:
        """
        Attempt to break cipher using rotation hyperparameter
        :param custom_key: key to be used, if known
        :param key_id: id of the key to be used for decryption
        :param rot: 'a' transforms to 'a' for 0 (default), to 'b' for 1
        :return: decrypted stream
        """

        if custom_key and key_id:
            raise(AttributeError("`custom_key` and `key_id` must be used exclusively"))

        # Attempt to decrypt the key
        if custom_key is None:
            key, _ = self.get_keys(key_id, rot=rot)
            # print("Guessing key: '%s'" % key)
        else:
            # Apply rotation to the custom key instead of the text
            key = "".join(chr(ord(k) + rot) for k in custom_key)

        # Apply the key to decode stream
        decoded_stream = vigener.decode(self.cipher_strip, key=key, rot=rot, strip=False)

        decoded_stream = vigener.destrip_blacklist(decoded_stream, feed_dict=self.blacklist_dict)

        return decoded_stream

    def get_keys(self, key_id=0, rot=0) -> (str, list):
        """
        Attempt to decrypt the Vigener key
        :param key_id: length of the key to be returned
        :param rot: 'a' transforms to 'a' for 0, to 'b' for 1 (default)
        :return: decrypted key with highest probability, list of possible keys for different lengths
        """

        # Estimate the key length
        key_len_list = self._est_key_len()
        if key_id >= len(key_len_list):
            return '', []

        # print("Estimated Key length: {}".format(key_len_list))

        key_list = []

        for k in key_len_list:
            key = ""

            # Find optimal shift for each character of the key
            for index in range(k):
                cipher_strip = self.cipher_strip[index::k]
                # Create new bag for stripped cipher
                cipher_strip_bag = Counter(self.default_alphabet_dct)
                cipher_strip_bag.update(cipher_strip)
                cipher_strip_list = sorted(cipher_strip_bag.items())  # Sort by key to match def_occurence ordering

                # Convert occurence to frequency and put it into deque to rotate easily
                strip_frequency = deque([v / len(cipher_strip_bag)*100 for k, v in cipher_strip_list])

                # Create shift matrix
                shift_list = []
                for i in range(len(strip_frequency)):
                    shift_list.append(strip_frequency.copy())
                    strip_frequency.rotate(1)

                shift_matrix = np.array(shift_list)
                shift_vector = np.matmul(shift_matrix, np.resize(self.letter_frequency,
                                                                 new_shape=shift_matrix[0].shape))
                # Get first five (magic) shifts and cache them
                shift_tuples = np.array([*enumerate(shift_vector)])
                shift_list = sorted(shift_tuples, key=lambda x: x[1], reverse=True)[:5]
                self.shift_dict[index] = [int(shift) for shift, _ in shift_list]

                shift_index = int(np.argmax(shift_vector))

                # Rotate letters to the peak position
                shift_sample = deque(k for k, v in cipher_strip_list)
                shift_sample.rotate(shift_index + rot)  # Number of rotations is shift index + rotation value

                key += shift_sample[0]

            key_list.append(key)

        return key_list[key_id], key_list

    def get_key_len(self, key_ord=0):
        """Get length of nth key where n is the order of the key"""
        est_len_list = self._est_key_len()
        if key_ord >= len(est_len_list):
            return -1

        return int(est_len_list[key_ord])

    def get_key_len_list(self, res=3):
        """Return list of estimated keys
        :param res: Number of results to be returned in the list
        """
        return [int(i) for i in self._est_key_len(res=res)]

    def _est_key_len(self, batch_count=2, res=3, gcd=False) -> list:
        """
        Attempts to estimate key len of cipher key based on coincidence matrix
        :param batch_count: Count of batches that will be created form the stream
        :param res: number of results to be returned
        :param gcd: eliminate multiplicators of key len using gcd
        :returns: List of possible key lengs sorted by probability
        """

        # Generate batches
        batch_size = len(self.cipher_strip) // batch_count
        batches = [self.cipher_strip[i * batch_size: (i + 1) * batch_size] for i in range(batch_count)]

        for batch_stream in batches:
            shift_array = [None] * (batch_size + 1)
            shift_array[0] = batch_stream

            co_matrix = np.empty(shape=(batch_size - 1,), dtype=np.float32)
            "Coincidance matrix"

            # Perform shifts
            shifted_str = batch_stream
            for i in range(len(batch_stream) - 1):  # The number of shifts is given by len of batch
                shifted_str = self.__shift_str(shifted_str)
                shift_array[i+1] = shifted_str

                # Get coincidance value
                #   Placing this here increases algorithm performance
                co_value = sum(c == shift_c for c, shift_c in zip(batch_stream, shifted_str))
                co_matrix[i] = co_value

            # Perform z-scale
            co_matrix -= co_matrix.mean()
            co_matrix /= co_matrix.std()

            # Get all the coincidence indexes where coincidence value >= 1
            co_values, = np.where(co_matrix >= 1)

            co_index_list = list(map((lambda t: t[1] - t[0]), zip(co_values, co_values[1:])))

            co_indexes = Counter(co_index_list)

            if gcd:
                # TODO eliminate multiplicators
                pass

            res = min(res, len(co_indexes))
            results = sorted(co_indexes.items(), key=lambda x: x[1], reverse=True)[:res]

            return [r[0] for r in results]

    @staticmethod
    def __shift_str(stream: str, rot=1, direction='r') -> str:
        """Performs cyclic shift in the given direction by given value"""

        if direction == 'r':
            _stream = stream[-rot:] + stream[:len(stream) - rot]
        elif direction == 'l':
            _stream = stream[rot:] + stream[:rot]
        else:
            raise AttributeError("Incorrect shift direction provided, "
                                 "expected one from ['l', 'r'], got %s" % direction)

        return _stream

    @staticmethod
    def __df_from_dict(dct: dict) -> pd.DataFrame:
        """Creates DataFrame from given dict replacing special symbols"""
        bag = dct.copy()

        return pd.DataFrame.from_dict(bag, orient='index')
