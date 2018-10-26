
from base64 import b64decode
from Crypto.Cipher import AES
from set2ch9 import padPKCS7, unpadPKCS7
from set1ch7 import ECBDecrypt

# encrypts the given data with AES-ECB with a given key
# data is padded before being encrypted
def aes_ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(padPKCS7(data, AES.block_size))

# xors two binary arrays and returns result
def xor_data(binary_data_1, binary_data_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(binary_data_1, binary_data_2)])

# encrypts data with AES-CBC with given key and iv
def aes_cbc_encrypt(data, key, iv):
    ciphertext = b''
    prev = iv
    # process the encryption block by block
    for i in range(0, len(data), AES.block_size):

        # always PKCS 7 pad the current plaintext block before proceeding
        curr_plaintext_block = padPKCS7(data[i:i + AES.block_size], AES.block_size)
        block_cipher_input = xor_data(curr_plaintext_block, prev)
        encrypted_block = aes_ecb_encrypt(block_cipher_input, key)
        ciphertext += encrypted_block
        prev = encrypted_block

    return ciphertext

# decrypts given AES-CBC data with given key and iv.
# checks for padding and adjusts plaintext as necessary.
def aes_cbc_decrypt(data, key, iv, unpad=True):
    plaintext = b''
    prev = iv

    # process the decryption block by block
    for i in range(0, len(data), AES.block_size):
        curr_ciphertext_block = data[i:i + AES.block_size]
        decrypted_block = ECBDecrypt(curr_ciphertext_block, key)
        plaintext += xor_data(prev, decrypted_block)
        prev = curr_ciphertext_block

    # return the plaintext either unpadded or left with the padding depending on the unpad flag
    return unpadPKCS7(plaintext) if unpad else plaintext


def main():
    iv = b'\x00' * AES.block_size
    key = b'YELLOW SUBMARINE'
    with open("inputText10.txt") as input_file:
        binary_data = b64decode(input_file.read())

    # compute and print the decrypted plaintext with the given input
    print(aes_cbc_decrypt(binary_data, key, iv).decode().rstrip())

if __name__ == '__main__':
    main()
