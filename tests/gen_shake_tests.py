'''Generates test methods in Rust from
"SHA-3 XOF Test Vectors for Byte-Oriented Output"
provided by "Cryptographic Algorithm Validation Program".

See: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing
     https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip

Tests are generated from "*ShortMsg.rsp", "*LongMsg.rsp" and "*VariableOut.rsp".
"*Monte.rsp" is omitted.
'''

import re

def parse_files(paths):
    bit_pat = re.compile(r'\[Outputlen\s+=\s+(\d+)]')
    testvectors = {}

    for path in paths:
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
                if not line.startswith('Output = '):
                    raise RuntimeError(f'expected MD {path!r} {line=}')
                else:
                    hash = line[9:].rstrip()

                testvectors[input_len] = (input_data, hashsize, hash)
    return testvectors


def print_test(hashfunc, testvectors):
    print()
    print('#[test]')
    print(f'fn test_{hashfunc}() {{')

    for input_len in testvectors:
        input_data, hashsize, hash = testvectors[input_len]

        print()
        if input_len <= 64:
            print(f'    let result = {hashfunc}(b"', end='')
            count = 0
            for octet in input_data:
                if count % 2 == 0:
                    print(f'\\x{octet}', end='')
                else:
                    print(octet, end='')
                count += 1
            print(f'".as_slice(), {hashsize});')
        else:
            print(f'    let result = {hashfunc}(b"\\')
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
            print(f'    ".as_slice(), {hashsize});')

        print(f'    assert_eq!("{hash}", stringify(&result));')
    print('}')


def parse_varfile(path):
    bit_pat = re.compile(r'\[Maximum Output Length \(bits\)\s+=\s+\d+]')
    testvectors = {}

    with path.open() as f:
        bit_found = False
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
                bit_found = True
                continue
            elif line.startswith('['):
                continue

            if not bit_found:
                raise RuntimeError(f'unknown error in {path!r} {line=}')

            # should have 4 consecutive lines
            if not line.startswith('COUNT = '):
                raise RuntimeError(f'expected COUNT in {path!r} {line=}')
            else:
                key = int(line[8:].rstrip())

            line = f.readline()
            if not line.startswith('Outputlen = '):
                raise RuntimeError(f'expected Outputlen in {path!r} {line=}')
            else:
                hashsize = int(line[12:].rstrip())

            line = f.readline()
            if not line.startswith('Msg = '):
                raise RuntimeError(f'expected Msg in {path!r} {line=}')
            else:
                input_data = line[6:].rstrip()

            line = f.readline()
            if not line.startswith('Output = '):
                raise RuntimeError(f'expected Output in {path!r} {line=}')
            else:
                hash = line[9:].rstrip()

            testvectors[key] = (input_data, hashsize, hash)
    return testvectors


def print_vartest(hashfunc, testvectors):
    print()
    print('#[test]')
    print(f'fn test_{hashfunc}_varout() {{')

    for key in testvectors:
        input_data, hashsize, hash = testvectors[key]

        print()
        print(f'    let result = {hashfunc}(b"\\')
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
        print(f'    ".as_slice(), {hashsize});')

        print(f'    assert_eq!("{hash}", stringify(&result));')
    print('}')


if __name__ == '__main__':
    from pathlib import Path

    testvectors = parse_files([Path('SHAKE128ShortMsg.rsp'), Path('SHAKE128LongMsg.rsp')])
    print_test('shake128', testvectors)

    testvectors = parse_varfile(Path('SHAKE128VariableOut.rsp'))
    print_vartest('shake128', testvectors)

    testvectors = parse_files([Path('SHAKE256ShortMsg.rsp'), Path('SHAKE256LongMsg.rsp')])
    print_test('shake256', testvectors)

    testvectors = parse_varfile(Path('SHAKE256VariableOut.rsp'))
    print_vartest('shake256', testvectors)
