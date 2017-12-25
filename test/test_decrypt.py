from cryptoanalysis.analysis import decryption

with open("samples/TIKcipher2a.txt") as sample:
    encoded_text = sample.read()

analyser = decryption.Analyser(encoded_text)
# decrypted = analyser.decipher(custom_key='onrktrmdgktrhl', rot=1)
decrypted = analyser.decipher(key_id=2, rot=1)

print("decrypted text: ", decrypted)
