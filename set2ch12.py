from base64 import b64decode
from set2ch10 import aes_ecb_encrypt
from set2ch9 import unpadPKCS7
from Crypto import Random
from Crypto.Cipher import AES
from set1ch8 import countECB

# uses the same key every time
class ECBOracle:
    def __init__(self, secret_padding):
        self._key = Random.new().read(AES.key_size[0])
        self._secret_padding = secret_padding

    # encrypts with AES after adding a fixed string to every plaintext
    def encrypt(self, data):
        return aes_ecb_encrypt(data + self._secret_padding, self._key)

# returns the length of a block for the block cipher used by the encryption_oracle.
# to find the length of a block, encrypt increasingly longer plaintexts until the size of the
# output ciphertext increases too. when this happens, compute the length of a
# block as the difference between this new length of the ciphertext and the length of the
# initial one. not very efficient, but it gets the job done.
def find_block_length(encryption_oracle):
    my_text = b''
    ciphertext = encryption_oracle.encrypt(my_text)
    initial_len = len(ciphertext)
    new_len = initial_len

    while new_len == initial_len:
        my_text += b'A'
        ciphertext = encryption_oracle.encrypt(my_text)
        new_len = len(ciphertext)

    return new_len - initial_len

# finds the next byte of the encrypted message that the oracle is appending to our plaintext.
def get_byte(block_length, curr_decrypted_message, encryption_oracle):
    # compute the number of characters that we want to use as input to make sure the first
    # character of the encrypted message is at the end of a block
    length_to_use = (block_length - (1 + len(curr_decrypted_message))) % block_length
    prefix = b'A' * length_to_use

    # compute the number of bytes that we will take from the fake and from the real ciphertexts
    # to compare them. ignore everything is beyond the byte we are trying to discover
    cracking_length = length_to_use + len(curr_decrypted_message) + 1

    # compute the real ciphertext that the oracle would output with the prefix we computed
    real_ciphertext = encryption_oracle.encrypt(prefix)

    # for each possible character
    for i in range(256):

        # compute our fake ciphertext, trying to obtain the same as the real ciphertext
        fake_ciphertext = encryption_oracle.encrypt(prefix + curr_decrypted_message + bytes([i]))

        # if we found a character that let us obtain the same ciphertext with our fake input
        if fake_ciphertext[:cracking_length] == real_ciphertext[:cracking_length]:

            # return that character as the next byte of the message
            return bytes([i])

    # if there was no match (most likely due to padding), return empty byte
    return b''

# performs the byte-at-a-time ECB decryption attack to discover the secret padding used by the oracle
def BTECB_decrypt(encryption_oracle):
    # Find the block length
    block_length = find_block_length(encryption_oracle)

    # encrypt a big enough plaintext of identical bytes to see if the ciphertext presents
    # repeated blocks; if it does, then it's probably using ECB.
    ciphertext = encryption_oracle.encrypt(bytes([0] * 64))
    assert countECB(ciphertext) > 0

    # the number of bytes to decrypt by breaking the encryption oracle =
    # the length of the ciphertext when we encrypt an empty message.
    mysterious_text_length = len(encryption_oracle.encrypt(b''))

    # and now we break it
    secret_padding = b''
    for i in range(mysterious_text_length):
        secret_padding += get_byte(block_length, secret_padding, encryption_oracle)

    # return the complete padding as bytes
    return secret_padding

# first, find the length of the block. second, find the encryption mode.
# third, decrypt the message byte-by-byte
def main():
    secret_padding = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGF"
                               "pciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IH"
                               "RvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    oracle = ECBOracle(secret_padding)
    discovered_secret_padding = BTECB_decrypt(oracle)

    # check
    assert unpadPKCS7(discovered_secret_padding) == secret_padding

if __name__ == '__main__':
    main()
