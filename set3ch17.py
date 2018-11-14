from set2ch9 import isPadded, unpadPKCS7
from set2ch10 import aes_cbc_encrypt, aes_cbc_decrypt
from random import randint
from Crypto import Random
from Crypto.Cipher.AES import block_size, key_size
from base64 import b64decode

class Oracle:

    def __init__(self, possible_inputs):
        self.iv = Random.new().read(block_size)
        self._key = Random.new().read(key_size[0])
        self._possible_inputs = possible_inputs

    def get_encrypted_message(self):
        # gets one of the random inputs and encrypts with a random key and IV with aes-128-cbc
        input = self._possible_inputs[randint(0, len(self._possible_inputs) - 1)].encode()
        return aes_cbc_encrypt(input, self._key, self.iv)

    def decrypt_and_check_padding(self, ciphertext, iv):
        # decrypts given message with the given IV and key generated when encrypted
        # returns true if the plaintext is padded with pkcs7 correctly
        plaintext = aes_cbc_decrypt(ciphertext, self._key, iv, False)
        return isPadded(plaintext)


def create_forced_previous_block(iv, guessed_byte, padding_len, found_plaintext):
    # creates forced block of the ciphertext, given as an IV to decrypt the next block.

    # get the index of the first character of the padding
    index_of_forced_char = len(iv) - padding_len

    # try to force the first character of the padding to be equal to the
    # length of the padding itself using the guessed byte given as input
    forced_character = iv[index_of_forced_char] ^ guessed_byte ^ padding_len

    # form the forced ciphertext by adding to it the forced character...
    output = iv[:index_of_forced_char] + bytes([forced_character])

    # ...and the characters that were forced before (for which we already know the plaintext)
    m = 0
    for k in range(block_size - padding_len + 1, block_size):

        # force each of the following characters of the IV so that the matching characters in
        # the next block will be decrypted to "padding_len"
        forced_character = iv[k] ^ found_plaintext[m] ^ padding_len
        output += bytes([forced_character])
        m += 1

    return output


def attack_padding_oracle(ciphertext, oracle):
    # decrypts the message by using the oracle's CBC encryption attack
    plaintext = b''

    # split the ciphertext in blocks of the AES block_size
    ciphertext_blocks = [oracle.iv] + [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    for c in range(1, len(ciphertext_blocks)):
        plaintext_block = b''   # the plaintext that correspondes to each ciphertext block

        # take each character of the ciphertext block (starting from the last one)
        # and decrypt it by forcing the previous block as IV
        for i in range(block_size - 1, -1, -1):

            # the padding len for the current character depends on how many characters of this
            # block (from right) that's already been decrypted
            padding_len = len(plaintext_block) + 1

            # find each possible character which gives us a correct padding
            possible_last_bytes = []
            for j in range(256):

                # create a IV with the guessed character j
                forced_iv = create_forced_previous_block(ciphertext_blocks[c - 1], j, padding_len, plaintext_block)

                # if the guessed character j gave a working padding, save it as one of the candidates
                if oracle.decrypt_and_check_padding(ciphertext_blocks[c], forced_iv) is True:
                    possible_last_bytes += bytes([j])

            # if more than one candidate is found, choose the best by trying
            # to force the next character too
            if len(possible_last_bytes) != 1:
                for byte in possible_last_bytes:
                    for j in range(256):
                        forced_iv = create_forced_previous_block(ciphertext_blocks[c - 1], j, padding_len + 1,
                                                                 bytes([byte]) + plaintext_block)

                        # if this gets a valid padding, then it's very likely that this is the
                        # correct candidate, so exit the loop
                        if oracle.decrypt_and_check_padding(ciphertext_blocks[c], forced_iv) is True:
                            possible_last_bytes = [byte]
                            break

            # get the new byte of the plaintext corresponding to the block and
            # add it on top of the decrypted text
            plaintext_block = bytes([possible_last_bytes[0]]) + plaintext_block

        # add the decrypted block to the plaintext
        plaintext += plaintext_block

    # return the unpadded plaintext bytes (in base 64)
    return unpadPKCS7(plaintext)

def main():
    with open("inputText13.txt") as f:
        strings = f.read().splitlines()

    oracle = Oracle(strings)
    result = attack_padding_oracle(oracle.get_encrypted_message(), oracle)

    # print the decryption of the message: if it's human readable then it worked.
    # (the numbers at the beginning  are present in every ciphertext of the input file)
    print(b64decode(result.decode()))

if __name__ == '__main__':
    main()
