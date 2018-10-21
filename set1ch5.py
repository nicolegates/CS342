import binascii
from set1ch2 import byteXOR

# XORs bytes against a key of set length
def repeatXOR(plaintext, key):
    ciphertext = b''
    i = 0

    for byte in plaintext:
        ciphertext += bytes([byte ^ key[i]])

        # cycles to the next byte in the key
        if i < len(key)-1:
            i += 1

        # cycles to the beginning of the key, if the last byte has been reached
        else:
            i = 0

    return ciphertext


def main():
    c = repeatXOR(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", b'ICE')

if __name__ == "__main__":
    main()
