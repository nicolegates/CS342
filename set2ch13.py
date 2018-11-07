from set2ch10 import aes_ecb_encrypt, aes_ecb_decrypt
from Crypto import Random
from Crypto.Cipher import AES


class ECBOracle:
    # this oracle uses the same key every time. the key is generated randomly during initialization.

    def __init__(self):
        self._key = Random.new().read(AES.key_size[0])

    def encrypt(self, email):
        # encrypts the given encoded user profile associated with the email with AES-128-ECB
        encoded = encode_KV(encode_profile(email))
        bytes_to_encrypt = encoded.encode()
        return aes_ecb_encrypt(bytes_to_encrypt, self._key)

    def decrypt(self, ciphertext):
        # decrypts with the given key
        return aes_ecb_decrypt(ciphertext, self._key)

def encode_KV(dict_object):
    # encodes a dictionary object to a kv encoded string, e.g. with input
    # {
    #    a: 'ay',
    #    b: 'bee',
    # }
    # the function will return
    #     a=ay&b=bee

    encoded_text = ''
    for item in dict_object.items():
        encoded_text += item[0] + '=' + str(item[1]) + '&'

    # return the encoded string, removing the last '&' character
    return encoded_text[:-1]

def parse_KV(encoded_text):
    # decodes a kv-encoded string into a dictionary
    output = {}
    traits = encoded_text.split('&')

    # add each trait to the dictionary, converting it to int as necessary
    for trait in traits:
        values = trait.split('=')
        key = int(values[0]) if values[0].isdigit() else values[0]
        value = int(values[1]) if values[1].isdigit() else values[1]
        output[key] = value

    return output

def encode_profile(email):
    # encodes the user's profile with kv-encoding, if given an email address
    email = email.replace('&', '').replace('=', '')     # Remove special characters to avoid injection
    return {
        'email': email,
        'uid': 10,
        'role': 'user'
    }

def ecb_cut_and_paste(encryption_oracle):
    """By cutting and pasting pieces of ciphertexts, forces a ciphertext of an admin user"""

    # The first plaintext that will be encrypted is:
    # block 1:           block 2 (pkcs7 padded):                             and (omitting the padding):
    # email=xxxxxxxxxx   admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b   &uid=10&role=user
    prefix_len = AES.block_size - len("email=")
    suffix_len = AES.block_size - len("admin")
    email1 = 'x' * prefix_len + "admin" + (chr(suffix_len) * suffix_len)
    encrypted1 = encryption_oracle.encrypt(email1)

    # The second plaintext that will be encrypted is:
    # block 1:           block 2:           block 3
    # email=master@me.   com&uid=10&role=   user\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c
    email2 = "master@me.com"
    encrypted2 = encryption_oracle.encrypt(email2)

    # The forced ciphertext will cut and paste the previous ciphertexts to be decrypted as:
    # block 1:           block 2:           block 3:
    # email=master@me.   com&uid=10&role=   admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    forced = encrypted2[:32] + encrypted1[16:32]

    return forced

def main():
    """Approach: use ecb cut and paste technique"""
    oracle = ECBOracle()
    forced_ciphertext = ecb_cut_and_paste(oracle)

    # Check that the attack works properly
    decrypted = oracle.decrypt(forced_ciphertext)
    parsed = parse_KV(decrypted.decode())
    assert parsed['role'] == 'admin'


if __name__ == '__main__':
    main()
