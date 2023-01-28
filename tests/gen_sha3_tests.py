'''Generates test methods in Rust from
"SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented Messages"
provided by "Cryptographic Algorithm Validation Program".

See: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing
     https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip

Tests are generated from "*ShortMsg.rsp" and "*LongMsg.rsp".
"*Monte.rsp" is omitted.
'''

import itertools
import re

def iter_files(path):
    return itertools.chain(
        path.glob('SHA3_*ShortMsg.rsp'),
        path.glob('SHA3_*LongMsg.rsp')
    )


def parse_file(path, testvectors):
    bit_pat = re.compile(r'\[L\s+=\s+(\d+)]')

    with path.open() as f:
        hashsize = None
        while True:
            line = f.readline()

            if len(line) == 0:
                break
            elif line.startswith('#'):
                continue
            elif line.isspace():
                continue

            bit_match = bit_pat.match(line)
            if bit_match:
                hashsize = int(bit_match.group(1))
                continue

            if not hashsize:
                raise RuntimeError(f'unknown error with {path!r} {line=}')

            # should have 3 consecutive lines
            if not line.startswith('Len = '):
                raise RuntimeError(f'expected Len {path!r} {line=}')
            else:
                input_len = int(line[6:].rstrip())

            line = f.readline()
            if not line.startswith('Msg = '):
                raise RuntimeError(f'expected Msg {path!r} {line=}')
            elif input_len == 0:
                input_data = ""
            else:
                input_data = line[6:].rstrip()

            line = f.readline()
            if not line.startswith('MD = '):
                raise RuntimeError(f'expected MD {path!r} {line=}')
            else:
                hash = line[5:].rstrip()

            if hashsize in testvectors:
                testvectors[hashsize][input_len] = (input_data, hash)
            else:
                testvectors[hashsize] = {input_len: (input_data, hash)}


if __name__ == '__main__':
    from pathlib import Path

    testvectors = {}
    for path in iter_files(Path('.')):
        parse_file(path, testvectors)

    for hashsize in testvectors:

        print()
        print('#[test]')
        print(f'fn test_sha{hashsize}() {{')

        for input_len in testvectors[hashsize]:
            input_data, hash = testvectors[hashsize][input_len]

            print()
            if input_len <= 64:
                print(f'    let result = sha{hashsize}(b"', end='')
                count = 0
                for octet in input_data:
                    if count % 2 == 0:
                        print(f'\\x{octet}', end='')
                    else:
                        print(octet, end='')
                    count += 1
                print('".as_slice());')
            else:
                print(f'    let result = sha{hashsize}(b"\\')
                count = 0
                for octet in input_data:
                    if count == 0:
                        print('        ', end='')
                    if count % 2 == 0:
                        print(f'\\x{octet}', end='')
                    else:
                        print(f'{octet}', end='')

                    count += 1
                    if count == 32:
                        count = 0
                        print('\\')
                if count != 0:
                    print('\\')
                print('    ".as_slice());')

            print(f'    assert_eq!("{hash}", stringify(&result));')
        print('}')
