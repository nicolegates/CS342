import binascii

def strXOR(x, y):
    # XORs two values together; takes two strings of bytes as input
    x_hex = binascii.unhexlify(x)
    y_hex = binascii.unhexlify(y)
    result = ''

    for i in range(len(x_hex)):
        result += chr(x_hex[i] ^ y_hex[i])

    result_byte = bytearray()
    result_byte.extend(result.encode())
    return result_byte

def byteXOR(x, y):
    # XORs two bytes together and returns the result; takes those two bytes as input
    return bytes([x ^ y])

def main():
    x = "1c0111001f010100061a024b53535009181c"
    y = "686974207468652062756c6c277320657965"
    z = "746865206b696420646f6e277420706c6179"

    x_hex = binascii.unhexlify(x)
    y_hex = binascii.unhexlify(y)
    z_hex = binascii.unhexlify(z)

    result = ''
    for i in range(0, len(x_hex)):
        result += chr(x_hex[i] ^ y_hex[i])

    result_byte = bytearray()
    result_byte.extend(result.encode())

    assert(result_byte == z_hex)

if __name__ == "__main__":
    main()
