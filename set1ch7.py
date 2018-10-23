from base64 import b64decode
from Crypto.Cipher import AES

# decrypts something with AES with a given key
def ECBDecrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return(cipher.decrypt(data))


def main():
    with open("inputText7.txt") as input_file:
        binary_data = b64decode(input_file.read())

    # compute and print the decrypted plaintext
    print(ECBDecrypt(binary_data, b'YELLOW SUBMARINE').decode().rstrip())


if __name__ == "__main__":
    main()
