from cryptoanalysis.analysis import decryption

with open("samples/TIKcipher2b.txt") as sample:
    encoded_text = sample.read()

analyser = decryption.Analyser(encoded_text)
print(analyser.get_keys())
decrypted = analyser.decipher(custom_key='churchill', rot=0)

print("decrypted text: ", decrypted)
