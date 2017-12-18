from cryptoanalysis.analysis import decryption

with open("samples/TIKcipher2a.txt") as sample:
    encoded_text = sample.read()

analyser = decryption.Analyser(encoded_text)
decrypted = analyser.decipher()

print("decrypted text: ", decrypted)
