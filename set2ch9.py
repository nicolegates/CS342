# pads message with PKCS#7 format with given block size
def padPKCS7(message, block_size):
    # if the length of the given message is already equal to the block size, don't pad
    if len(message) == block_size:
        return message

    # otherwise compute the padding byt, pad the message, and return it
    ch = block_size - len(message) % block_size
    return message + bytes([ch] * ch)

# checks if a message is padded
def isPadded(binData):
    # take what we expect to be the padding by removing the message
    padding = binData[-binData[-1]:]

    # check that all the bytes in the range indicated by the padding are equal to the padding value itself
    return all(padding[b] == len(padding) for b in range(0, len(padding)))

# unpads a message and returns it
def unpadPKCS7(data):
    if len(data) == 0:
        raise Exception("The input data must contain at least one byte")

    if not isPadded(data):
        return data

    padding_len = data[len(data) - 1]
    return data[:-padding_len]


def main():
    message = b"YELLOW SUBMARINE"
    b = padPKCS7(message, 20)
    print(b)

if __name__ == "__main__":
    main()
