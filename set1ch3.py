import binascii
from set1ch2 import byteXOR

# frequency of letters in the English language
freqs = {
    'a': 0.0651738,
    'b': 0.0124248,
    'c': 0.0217339,
    'd': 0.0349835,
    'e': 0.1041442,
    'f': 0.0197881,
    'g': 0.0158610,
    'h': 0.0492888,
    'i': 0.0558094,
    'j': 0.0009033,
    'k': 0.0050529,
    'l': 0.0331490,
    'm': 0.0202124,
    'n': 0.0564513,
    'o': 0.0596302,
    'p': 0.0137645,
    'q': 0.0008606,
    'r': 0.0497563,
    's': 0.0515760,
    't': 0.0729357,
    'u': 0.0225134,
    'v': 0.0082903,
    'w': 0.0171272,
    'x': 0.0013692,
    'y': 0.0145984,
    'z': 0.0007836,
    ' ': 0.1918182
}

# Returns the sum of probabilities given the frequencies above
def score(ciphertext):
    score = 0
    for i in ciphertext:
        # sets each char to lowercase
        char = chr(i).lower()

        # checks for char in freqs and adds them to the score
        if char in freqs:
            score += freqs[char]
    return score

# XORs each byte of the ciphertext with the given key value
def babyXOR(ciphertext, key):
    output = b''
    for char in ciphertext:
        output += byteXOR(char, key)
    return output

# Decrypts ciphertext with every single possible byte and returns the plaintext
def actualXOR(ciphertext):
    possibilities = []

    # builds on babyXOR, except this time it does it for every key, not just one
    for key_possibility in range(256):
        plaintext_possibility = babyXOR(ciphertext, key_possibility)
        possibility_score = score(plaintext_possibility)

        result = {
            'key': key_possibility,
            'score': possibility_score,
            'plaintext': plaintext_possibility
        }

        # once a result has been calculated, adds it to the possible correct key
        possibilities.append(result)

    # returns only the possibility with the highest score (i.e. most similar to English)
    return sorted(possibilities, key=lambda c: c['score'], reverse=True)[0]

def main():
    ciphertext = binascii.unhexlify("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    plaintext = actualXOR(ciphertext)
    print(plaintext)

if __name__ == "__main__":
    main()
