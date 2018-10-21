import codecs

# a general function that converts a given string x that is hex into base-64
def convert(x):
    b64 = codecs.encode(codecs.decode(x, 'hex'), 'base64').decode()
    return b64

def main():
    # the base code: this converts a string in hex to base-64, returning it as a string.
    hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    b64 = codecs.encode(codecs.decode(hex, 'hex'), 'base64').decode()
    print(b64)

if __name__ == "__main__":
    main()
