from cryptoanalysis.analysis import decryption

with open("samples/TIKcipher2a.txt") as sample:
    encoded_text = sample.read()

analyser = decryption.Analyser(encoded_text)
print(analyser.get_keys())
decrypted = analyser.decipher(key_id=2)

print("decrypted text: ", decrypted)
