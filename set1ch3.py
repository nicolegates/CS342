import binascii
from set1ch2 import byteXOR

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

def score(ciphertext):
    # Returns the sum of probabilities given the frequencies above
    score = 0
    for i in ciphertext:
        char = chr(i).lower()
        if char in freqs:
            score += freqs[char]
    return score

def babyXor(ciphertext, key):
    # XORs each byte of the ciphertext with the given key value
    output = b''

    for char in ciphertext:
        output += byteXOR(char, key)

    return output


def actualXor(ciphertext):
    # Decrypts ciphertext with every single possible byte and returns the plaintext
    candidates = []

    for key_candidate in range(256):
        plaintext_candidate = babyXor(ciphertext, key_candidate)
        candidate_score = score(plaintext_candidate)

        result = {
            'key': key_candidate,
            'score': candidate_score,
            'plaintext': plaintext_candidate
        }

        candidates.append(result)

    # Return only the candidate with the highest score
    return sorted(candidates, key=lambda c: c['score'], reverse=True)[0]

def main():
    ciphertext = binascii.unhexlify("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    plaintext = actualXor(ciphertext)
    print(plaintext)

    assert plaintext['plaintext'].rstrip() == b"Cooking MC's like a pound of bacon"

if __name__ == "__main__":
    main()
