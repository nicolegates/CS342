#import set1ch1
#import set1ch2\
import binascii

input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
b = list(input)
#b = bytearray()
#b.extend(input.encode())
#print(b)
print(binascii.unhexlify(input))

#for i in range(len(b)):
    #print(ord(b[i]))
