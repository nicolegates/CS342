import binascii
from set1ch3 import actualXor

# takes lines within the file and uses the XOR attack from set 3 to get a plaintext.
# gets a score for each plaintext and adds it to the possible correct answers.
# finally returns the plaintext with the highest English score.
def findText(filename):
    possibilities = []
    
    # XORs bytes together with a given key and a given line from the file
    for string in filename:
        possibilities.append(actualXor(string))

    # return only the possibility with the highest score
    return sorted(possibilities, key=lambda c: c['score'], reverse=True)[0]

def main():
    ciphertexts = [binascii.unhexlify(line.strip()) for line in open("inputText4.txt")]
    plaintext = findText(ciphertexts)
    print(plaintext)

if __name__ == "__main__":
    main()
