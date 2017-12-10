"""Decryption tools"""

import numpy as np
import pandas as pd

from collections import Counter, deque
from matplotlib import pyplot as plt
from cipher import vigener


class Analyser:

    def __init__(self, cipher: str = None, cipher_type='mono', lang='en'):
        """
        Analyser class providing tools to analyse and decrypt ciphers
        :param cipher: encoded stream to be decrypted
        :param cipher_type: mono alphabetic by default
        :param lang: language to choose
        """
        self.cipher_strip, self.blacklist_dict = vigener.strip_blacklist(cipher)

        self.type = cipher_type
        self.lang = lang

        _lang_df = pd.read_csv('meta/{lang}.csv'.format(lang=self.lang))

        self.alphabet = _lang_df.letters.values
        self.letter_frequency = _lang_df.occurence.values
        "DataFrame with cipher character frequency"

        self.default_alphabet_dct = dict(zip(self.alphabet, (0 for _ in range(len(self.alphabet)))))

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

    def decipher(self, rot=1) -> str:
        """
        Attempt to break cipher using rotation hyperparameter
        :param rot: 'a' transforms to 'a' for 0, to 'b' for 1 (default)
        :return: decrypted stream
        """

        # Attempt to decrypt the key
        key = self.decrypt_key()
        print("Guessing key: '%s'" % key)

        # Apply the key to decode stream
        decoded_stream = vigener.decode(self.cipher_strip, key=key, rot=rot, strip=False)

        decoded_stream = vigener.destrip_blacklist(decoded_stream, feed_dict=self.blacklist_dict)

        return decoded_stream

    def decrypt_key(self) -> str:
        """
        Attempt to decrypt the Vigener key   # TODO return multiple keys?
        :return: decrypted key
        """

        # Estimate the key length
        est_length_list = self._est_key_len()

        print("Estimated Key length: {}".format(est_length_list))

        # TODO: handle choosing key by user
        key_len = est_length_list[0]

        key = ""
        # Find optimal shift for each character of the key
        for index in range(key_len):
            cipher_strip = self.cipher_strip[index::key_len]
            # Create new bag for stripped cipher
            cipher_strip_bag = Counter(self.default_alphabet_dct)
            cipher_strip_bag.update(cipher_strip)
            cipher_strip_list = sorted(cipher_strip_bag.items())  # Sort by key to match def_occurence ordering

            # Convert occurence to frequency and put it into deque to rotate easily
            strip_frequency = deque([v / len(cipher_strip_bag)*100 for k, v in cipher_strip_list])

            # TODO: handle shifts by user
            # Create shift matrix
            shift_list = []
            for i in range(len(strip_frequency)):
                shift_list.append(strip_frequency.copy())
                strip_frequency.rotate(1)

            shift_matrix = np.array(shift_list)
            shift_vector = np.matmul(shift_matrix, np.resize(self.letter_frequency, new_shape=shift_matrix[0].shape))

            shift_index = int(np.argmax(shift_vector))

            # Rotate to the peak position letters to the peak position
            shift_sample = deque(k for k, v in cipher_strip_list)
            shift_sample.rotate(shift_index + 1)  # Number of rotations is shift index + 1

            key += shift_sample[0]

        return key

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
