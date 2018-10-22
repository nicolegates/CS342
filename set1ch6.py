from base64 import b64decode
from set1ch3 import actualXOR, score
from set1ch5 import repeatXOR
from itertools import combinations

# calculates hamming distance between two strings of equal length
def hamDistance(binseq1, binseq2):
    assert len(binseq1) == len(binseq2)
    dist = 0

    for bit1, bit2 in zip(binseq1, binseq2):
        diff = bit1 ^ bit2
        dist += sum([1 for bit in bin(diff) if bit == '1'])

    return dist

# breaks the repeating key XOR encryption
def breakRepeatXOR(bin_data):
    normalized_distances = {}

    # for each key size, taken from suggested range
    for key_size in range(2, 41):

        # take the first four key size worth of bytes, as suggested
        chunks = [bin_data[i:i + key_size] for i in range(0, len(bin_data), key_size)][:4]

        # sum the hamming distances between each pair of chunks
        distance = 0

        # combine two pairs of chunks into actual pairs for comparison
        pairs = combinations(chunks, 2)
        for (x, y) in pairs:
            distance += hamDistance(x, y)

        # compute the average distance
        distance /= 6

        # normalize the result by dividing by key size, as suggested
        normalized_distance = distance / key_size

        # store the normalized distance for the given key size
        normalized_distances[key_size] = normalized_distance

    # the key sizes with the smallest normalized edit distances are the most likely ones,
    # so sort them and take the top three (as they are the most likely)
    possible_key_sizes = sorted(normalized_distances, key=normalized_distances.get)[:3]
    possibilities = []

    # find the most likely key of the three taken
    for d in possible_key_sizes:
        key = b''

        # break the ciphertext into blocks of key size length
        for i in range(d):
            block = b''

            # make a block that is the ith byte of every block
            for j in range(i, len(bin_data), d):
                block += bytes([bin_data[j]])

            # brute force through each block as if it was single-character XOR
            key += bytes([actualXOR(block)['key']])

        # store the possible plaintext obtained from using this key size
        possibilities.append((repeatXOR(bin_data, key), key))

    # returns only the possibility with the highest score
    return max(possibilities, key=lambda k: score(k[0]))


def main():
    with open("inputText6.txt") as input_file:
        data = b64decode(input_file.read())

    # compute and print the result of the attack
    result = breakRepeatXOR(data)
    print("Key =", result[1].decode())
    print(result[0].decode().rstrip())


if __name__ == "__main__":
    main()
