"""Simplistic RESTful API"""

from flask import Flask, jsonify
from flask_restful import Resource, Api

from cryptoanalysis.analysis import decryption


app = Flask(__name__)
api = Api(app)


class Frequency(Resource):
    def get(self, file):
        # Set up analyzer
        analyser = decryption.Analyser(fname='samples/%s' % file)
        result_arr = []
        result_arr.append({'cipher': analyser.cipher})
        result_arr.append({'cipher_type': 'Vigener'})
        for k, v in analyser.get_char_frequency().items():
            result_arr.append({'letter': k.upper(), 'frequency': v})

        return jsonify(result_arr)


class Keys(Resource):
    def get(self, file):
        # Set up analyzer
        analyser = decryption.Analyser(fname='samples/%s' % file)
        result = {'cipher_type': 'Vigener', 'cipher': analyser.cipher}
        result['key_len_list'] = analyser.get_key_len_list()
        key_select, key_list = analyser.get_keys()
        result['key'], result['key_list'] = key_select, key_list

        return jsonify(result)


class KeyGetter(Resource):
    def get(self, file, key_id):
        # Set up analyzer
        analyser = decryption.Analyser(fname='samples/%s' % file)
        result = {'cipher_type': 'Vigener', 'cipher': analyser.cipher}
        key_id = int(key_id)
        result['cipher'] = analyser.get_cipher()
        result['key'], _ = analyser.get_keys(key_id=key_id)

        return jsonify(result)


class Decryptor(Resource):
    def get(self, file, key, rot):
        # Set up analyzer
        analyser = decryption.Analyser(fname='samples/%s' % file)
        result = {'cipher_type': 'Vigener', 'cipher': analyser.cipher}
        rot = int(rot)
        result['decrypted_text'] = analyser.decipher(custom_key=key, rot=rot)

        return jsonify(result)


class KeyLenGetter(Resource):
    def get(self, file, key_id):
        # Set up analyzer
        analyser = decryption.Analyser(fname='samples/%s' % file)
        result = {'cipher_type': 'Vigener', 'cipher': analyser.cipher}
        key_id = int(key_id)
        est_len = analyser.get_key_len(key_ord=key_id)
        if est_len < 0:
            result['Error'] = 'Index out of range'
        else:
            result['key_len'] = est_len
        return jsonify(result)


api.add_resource(Frequency, '/frequency/file=<file>')  # frequency analysis
api.add_resource(Keys, '/keys/file=<file>')  # list of key lengths
api.add_resource(KeyGetter, '/keys/file=<file>key_id=&<key_id>')  # key len by order
api.add_resource(KeyLenGetter, '/keys/len/file=<file>&key_id=<key_id>')  # key len by order
api.add_resource(Decryptor, '/decrypt/file=<file>&key=<key>&rot=<rot>')


if __name__ == '__main__':
    app.run(port='5002')

