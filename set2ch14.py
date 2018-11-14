from base64 import b64decode
from set2ch10 import aes_ecb_encrypt
from set2ch9 import unpadPKCS7
from random import randint
from Crypto import Random
from set1ch8 import countECB
from set2ch12 import find_block_length, ECBOracle


class HarderECBOracle(ECBOracle):

    def __init__(self, secret_padding):
        super(HarderECBOracle, self).__init__(secret_padding)
        self._random_prefix = Random.new().read(randint(0, 255))

    def encrypt(self, data):
        # prepends a randomly-generated fixed string, appends a given fixed string, and
        # encrypts with aes-128-ecb
        return aes_ecb_encrypt(self._random_prefix + data + self._secret_padding, self._key)


def get_next_byte(prefix_length, block_length, curr_decrypted_message, encryption_oracle):
    # gets next byte that the oracle is appending to the plaintext

    # computes the number of characters needed in the input to have the first
    # unknown byte of the plaintext be at the end of the block
    length_to_use = (block_length - prefix_length - (1 + len(curr_decrypted_message))) % block_length
    input = b'A' * length_to_use

    # computes the number of bytes to take from the fake and real ciphertexts for comparison
    cracking_length = prefix_length + length_to_use + len(curr_decrypted_message) + 1

    # compute the real ciphertext that the oracle would output with the given input
    real_ciphertext = encryption_oracle.encrypt(input)

    # for each possible character:
    for i in range(256):

        # compute the fake ciphertext and attempt to obtain the same as the real ciphertext
        fake_ciphertext = encryption_oracle.encrypt(input + curr_decrypted_message + bytes([i]))

        # if a character that, used in the fake input, obtains the real ciphertext...
        if fake_ciphertext[:cracking_length] == real_ciphertext[:cracking_length]:

            # ... return that character as the next byte of the message
            return bytes([i])

    # if there was no match (most likely due to padding), return empty byte
    return b''


def are_blocks_equal(ciphertext, block_length):
    # checks if a ciphertext has two consecutive blocks of equal value
    for i in range(0, len(ciphertext) - 1, block_length):
        if ciphertext[i:i+block_length] == ciphertext[i+block_length:i+2*block_length]:
            return True

    return False


def find_prefix_length(encryption_oracle, block_length):
    # finds length of (randomly-generated) prefix encryption_oracle added to each plaintext
    # before encrypting. Two steps:
    # 1. search block where prefix ends
    # 2. find index of where prefix ends

    # use the oracle to encrypt an empty message and a 1 character message
    # to find the index of the block where the prefix ends
    ciphertext1 = encryption_oracle.encrypt(b'')
    ciphertext2 = encryption_oracle.encrypt(b'a')

    # find first block where the ciphertexts are different; this is where
    # the prefix ended
    prefix_length = 0
    for i in range(0, len(ciphertext2), block_length):
        if ciphertext1[i:i+block_length] != ciphertext2[i:i+block_length]:
            prefix_length = i
            break

    # find index where the prefix ended by:
    # 1. encrypt indentical bytes with size 2 * (block_length)
    # 2. increase size by incremental offset
    # 3. continue until bytes are shifted to be autonomous blocks, i.e.
    #       encrypted in the same way
    for i in range(block_length):
        fake_input = bytes([0] * (2 * block_length + i))
        ciphertext = encryption_oracle.encrypt(fake_input)

        # if the bytes have shifted enough, compute the precise index where the prefix ends
        # inside its last block (equal to block_length - i).
        if are_blocks_equal(ciphertext, block_length):
            return prefix_length + block_length - i if i != 0 else prefix_length

    raise Exception('The oracle is not using ECB')


def byte_at_a_time_ecb_decryption_v2(encryption_oracle):
    # byte-at-a-time ebc decryption attack to discover secret padding used by the oracle

    # find the block length
    block_length = find_block_length(encryption_oracle)

    # Detect if the oracle encrypts with ECB mode by encrypting a big enough (more
    # than three block sizes) plaintext of identical bytes, because if the ciphertext
    # presents repeated blocks it's probably using ECB.
    ciphertext = encryption_oracle.encrypt(bytes([0] * 64))
    assert countECB(ciphertext) > 0

    # the number of bytes that need to be decrypted by breaking the encryption oracle
    # will be equal to the length of the ciphertext when an empty message is encrypted
    # subtracted by the length of the prefix.
    prefix_length = find_prefix_length(encryption_oracle, block_length)
    mysterious_text_length = len(encryption_oracle.encrypt(b'')) - prefix_length

    # all information needed to crack the ECB encryption oracle byte by byte
    # is used here.
    secret_padding = b''
    for i in range(mysterious_text_length):
        secret_padding += get_next_byte(prefix_length, block_length, secret_padding, encryption_oracle)

    # return the complete padding as bytes
    return secret_padding


def main():
    secret_padding = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGF"
                               "pciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IH"
                               "RvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    oracle = HarderECBOracle(secret_padding)
    discovered_secret_padding = byte_at_a_time_ecb_decryption_v2(oracle)

    # Check if the attack works correctly
    assert unpadPKCS7(discovered_secret_padding) == secret_padding


if __name__ == '__main__':
    main()
