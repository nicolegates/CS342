from set2ch9 import isPadded

def main():
    # wrote this method previously
    assert isPadded(b'ICE ICE BABY\x04\x04\x04\x04') is True
    assert isPadded(b'ICE ICE BABY\x05\x05\x05\x05') is False
    assert isPadded(b'ICE ICE BABY\x01\x02\x03\x04') is False
    assert isPadded(b'ICE ICE BABY') is False

if __name__ == '__main__':
    main()
