from set2ch10 import aes_cbc_encrypt, aes_cbc_decrypt
from Crypto import Random
from Crypto.Cipher import AES


class Oracle:

    def __init__(self):
        self._key = Random.new().read(AES.key_size[0])
        self._iv = Random.new().read(AES.block_size)
        self._prefix = "comment1=cooking%20MCs;userdata="
        self._suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

    def encrypt(self, data):
        # adds prefix and suffix and encrypts with aes-128-cbc
        data = data.replace(';', '').replace('=', '')  # remove special characters to avoid injection
        plaintext = (self._prefix + data + self._suffix).encode()
        return aes_cbc_encrypt(plaintext, self._key, self._iv)

    def decrypt_and_check_admin(self, ciphertext):
        # decrypts and returns if ';admin=true;' is in the string
        data = aes_cbc_decrypt(ciphertext, self._key, self._iv)
        return b';admin=true;' in data


def find_block_length(encryption_oracle):
    # returns length of cipher used by encryption_oracle by
    # 1. encrypting longer and longer plaintexts until output ciphertext increases
    # 2. computing length of the block by finding the difference between the
    # new length and the initial length.

    text = ''
    ciphertext = encryption_oracle(text)
    initial_len = len(ciphertext)
    new_len = initial_len

    while new_len == initial_len:
        text += 'A'
        ciphertext = encryption_oracle(text)
        new_len = len(ciphertext)

    return new_len - initial_len


def find_prefix_length(encryption_oracle, block_length):
    # returns prefix length used by encryption_oracle

    # encrypt two different ciphertexts
    ciphertext_a = encryption_oracle('A')
    ciphertext_b = encryption_oracle('B')

    # find their common length
    common_len = 0
    while ciphertext_a[common_len] == ciphertext_b[common_len]:
        common_len += 1

    # check that common length is a multiple of the block length
    common_len = int(common_len / block_length) * block_length

    # try to add an increasing number of common bytes to the plaintext until
    # the two ciphertexts have one extra identical block
    for i in range(1, block_length + 1):
        ciphertext_a = encryption_oracle('A' * i + 'X')
        ciphertext_b = encryption_oracle('A' * i + 'Y')

        # if there is one more identical block, it will mean that by adding i bytes
        # made the common input the same length multiple of a block size -- including
        # prefix
        if ciphertext_a[common_len:common_len + block_length] == ciphertext_b[common_len:common_len + block_length]:
            return common_len + (block_length - i)


def bitflip_cbc(encryption_oracle):
    # cbc bit flip attack by accomplishing admin privileges to the decrypted data

    # Get the length of a block and the length of the prefix
    block_length = find_block_length(encryption_oracle.encrypt)
    prefix_length = find_prefix_length(encryption_oracle.encrypt, block_length)

    # Compute the number of bytes to add to the prefix to make its length a multiple of block_length
    additional_prefix_bytes = (block_length - (prefix_length % block_length)) % block_length
    total_prefix_length = prefix_length + additional_prefix_bytes

    # Compute the number of bytes to add to the plaintext to make its length a multiple of block length
    plaintext = "?admin?true"
    additional_plaintext_bytes = (block_length - (len(plaintext) % block_length)) % block_length

    # Make the plaintext long one block_length and encrypt it
    final_plaintext = additional_plaintext_bytes * '?' + plaintext
    ciphertext = encryption_oracle.encrypt(additional_prefix_bytes * '?' + final_plaintext)

    # Because XORing a byte with itself produces zero, we can produce the byte that we want
    # by changing the bytes of the block before the plaintext
    semicolon = ciphertext[total_prefix_length - 11] ^ ord('?') ^ ord(';')
    equals = ciphertext[total_prefix_length - 5] ^ ord('?') ^ ord('=')

    # Put the pieces of our forged ciphertext together to generate the full ciphertext
    forced_ciphertext = ciphertext[:total_prefix_length - 11] + bytes([semicolon]) + \
                        ciphertext[total_prefix_length - 10: total_prefix_length - 5] + \
                        bytes([equals]) + ciphertext[total_prefix_length - 4:]

    return forced_ciphertext

def main():
    encryption_oracle = Oracle()
    forced_ciphertext = bitflip_cbc(encryption_oracle)

    # Check if the ciphertext was forced properly
    assert encryption_oracle.decrypt_and_check_admin(forced_ciphertext)

if __name__ == '__main__':
    main()
