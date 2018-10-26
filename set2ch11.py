from set1ch8 import countECB
from set2ch10 import aes_ecb_encrypt, aes_cbc_encrypt
from random import randint
from Crypto.Cipher.AES import block_size
from Crypto import Random

# oracle which encrypts the given data using a random AES method (chosen between ECB and CBC),
# a random key, a random iv (in case of CBC), and also adds a random padding before and after the plaintext.
class AesEncryptionOracle:

    @staticmethod
    def encrypt(plaintext):
        # add a random padding before and after the plaintext
        padded_plaintext = AesEncryptionOracle._pad_with_bytes(plaintext)

        # generate a random key
        key = Random.new().read(block_size)

        # encrypt randomly with ECB or CBC
        if randint(0, 1) == 0:
            return "ECB", aes_ecb_encrypt(padded_plaintext, key)
        else:
            return "CBC", aes_cbc_encrypt(padded_plaintext, key, Random.new().read(block_size))

    #@staticmethod
    # pads randomly on both sides of plaintext
    def _pad_with_bytes(binary_data):
        return Random.new().read(randint(5, 10)) + binary_data + Random.new().read(randint(5, 10))

# checks whether ciphertext was encrypted with ECB or CBC.
def detect_cipher(ciphertext):
    if countECB(ciphertext) > 0:
        return "ECB"
    else:
        return "CBC"


def main():
    oracle = AesEncryptionOracle()

    # choose a repeating input data; this allows us to check for ECB; ECB will have
    # repetitions, which detect_cipher looks for
    input_data = bytes([0]*64)

    for _ in range(1000):
        encryption_used, ciphertext = oracle.encrypt(input_data)
        encryption_detected = detect_cipher(ciphertext)

if __name__ == '__main__':
    main()
