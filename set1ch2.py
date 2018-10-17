x = "1c0111001f010100061a024b53535009181c"
y = "686974207468652062756c6c277320657965"

# create byte arrays
b1 = bytearray()
b2 = bytearray()

# convert strings into byte arrays
b1.extend(x.encode())
b2.extend(y.encode())

# XOR each byte in the byte arrays against each other
for i in range(len(b1)):
    b1[i] = b1[i] ^ b2[i]

#print byte array containing XORed
print(b1)

# the XOR function: takes two values in hex, XORs them, and returns
# a byte array containing the XORed values
def XOR(x, y):
    b1 = bytearray()
    b2 = bytearray()
    b1.extend(x.encode())
    b2.extend(y.encode())
    for i in range(len(b1)):
        b1[i] = b1[i] ^ b2[i]

    return b1
