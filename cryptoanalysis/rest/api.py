"""Simplistic REST API"""

from flask import Flask, jsonify
from flask_restful import Resource, Api, reqparse

from cryptoanalysis.analysis import decryption


APP = Flask(__name__)
API = Api(APP)

PARSER = reqparse.RequestParser()
PARSER.add_argument('data')

ANALYSER = decryption.Analyser()
DEFAULT_RESPONSE = dict()


def _create_letter_freq_arr(letters: list, frequency: list) -> list:
    _result = list()
    assert len(letters) == len(frequency)
    for l, f in zip(letters, frequency):
        _result.append({'letter': l.upper(), 'frequency': f})

    return _result


def _load_default_response(analyser: decryption.Analyser):
    global DEFAULT_RESPONSE
    _response = {
        'cipher': analyser.cipher, 'cipher_type': 'Vigener',
        'lang': analyser.lang, 'alphabet': analyser.alphabet.tolist(),
        'lang_letter_freq': _create_letter_freq_arr(
            analyser.alphabet.tolist(),
            analyser.letter_frequency.tolist()
        )
    }

    DEFAULT_RESPONSE.update(_response)


_load_default_response(ANALYSER)


class Analysis(Resource):
    @staticmethod
    def put():
        global ANALYSER, DEFAULT_RESPONSE

        args = PARSER.parse_args()
        if 'data' not in args:
            return {}, 201

        ANALYSER = decryption.Analyser(cipher=args['data'])
        _load_default_response(ANALYSER)

        return jsonify(DEFAULT_RESPONSE)

    @staticmethod
    def get():
        return jsonify(DEFAULT_RESPONSE)


class Frequency(Resource):
    @staticmethod
    def get():
        char_freq = ANALYSER.get_char_frequency()
        result_arr = _create_letter_freq_arr(
            char_freq.keys(), char_freq.values()
        )

        return jsonify(result_arr)


class Keys(Resource):
    @staticmethod
    def get():
        result = dict()
        result['key_len_list'] = ANALYSER.get_key_len_list()
        key_select, key_list = ANALYSER.get_keys()
        result['key'], result['key_list'] = key_select, key_list

        return jsonify(result)


class KeyGetter(Resource):
    @staticmethod
    def get(key_id):
        result = {'cipher_type': 'Vigener', 'cipher': ANALYSER.cipher}
        key_id = int(key_id)
        result['cipher'] = ANALYSER.get_cipher()
        result['key'], _ = ANALYSER.get_keys(key_id=key_id)

        return jsonify(result)


class Decrypter(Resource):
    @staticmethod
    def get(key, rot):
        result = dict([('cipher_type', 'Vigener'), ('cipher', ANALYSER.cipher)])
        result['decrypted_text'] = ANALYSER.decipher(custom_key=key, rot=rot)

        return jsonify(result)


class KeyLenGetter(Resource):
    @staticmethod
    def get(key_id):
        result = {'cipher_type': 'Vigener', 'cipher': ANALYSER.cipher}
        est_len = ANALYSER.get_key_len(key_ord=key_id)
        if est_len < 0:
            result['Error'] = 'Index out of range'
        else:
            result['key_len'] = est_len
        return jsonify(result)


# Add resources
API.add_resource(Analysis, '/')
API.add_resource(Frequency, '/frequency')  # frequency analysis
API.add_resource(Keys, '/keys')  # list of key lengths
API.add_resource(KeyGetter, '/keys/<int:key_id>')  # key len by order
API.add_resource(KeyLenGetter, '/keys/len/<int:key_id>')  # key len by order
API.add_resource(Decrypter, '/decrypt/key=<string:key>&rot=<int:rot>')  # decrypter


if __name__ == '__main__':
    APP.run(port='5002')

