from Crypto.Cipher.AES import block_size

# counts the number of repeated chunks of the ciphertext and returns it.
def countECB(ciphertext):
    chunks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    number_of_duplicates = len(chunks) - len(set(chunks))
    return number_of_duplicates

# detects which ciphertext among the given one is the one most likely encrypted with AES in ECB mode.
def detectECB(ciphertexts):
    best = (-1, 0)     # index of best candidate, repetitions of best candidate

    # for each given ciphertext...
    for i in range(len(ciphertexts)):

        # count the block repetitions
        repetitions = countECB(ciphertexts[i])

        # keep  ciphertext with most repetitions
        best = max(best, (i, repetitions), key=lambda t: t[1])

    # return ciphertext with most repetitions
    return best


def main():
    ciphertexts = [bytes.fromhex(line.strip()) for line in open("inputText8.txt")]
    result = detectECB(ciphertexts)

    print("The encrypted ciphertext is at", result[0],
          "which has", result[1], "repetitions")

if __name__ == "__main__":
    main()
