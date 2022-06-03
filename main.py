def hex2bin(s):
    """
    Hexadecimal to binary conversion
    :param s: Hexadecimal number
    :return:Binary number
    """
    mp = {'0': "0000",
          '1': "0001",
          '2': "0010",
          '3': "0011",
          '4': "0100",
          '5': "0101",
          '6': "0110",
          '7': "0111",
          '8': "1000",
          '9': "1001",
          'A': "1010",
          'B': "1011",
          'C': "1100",
          'D': "1101",
          'E': "1110",
          'F': "1111"}
    bin_str = ""
    for j in range(len(s)):
        bin_str = bin_str + mp[s[j]]
    return bin_str


def bin2hex(s):
    """
    Binary to hexadecimal conversion
    :param s: Binary number
    :return: Hexadecimal number
    """
    mp = {"0000": '0',
          "0001": '1',
          "0010": '2',
          "0011": '3',
          "0100": '4',
          "0101": '5',
          "0110": '6',
          "0111": '7',
          "1000": '8',
          "1001": '9',
          "1010": 'A',
          "1011": 'B',
          "1100": 'C',
          "1101": 'D',
          "1110": 'E',
          "1111": 'F'}
    hex_str = ""
    for j in range(0, len(s), 4):
        ch = ""
        ch = ch + s[j]
        ch = ch + s[j + 1]
        ch = ch + s[j + 2]
        ch = ch + s[j + 3]
        hex_str = hex_str + mp[ch]

    return hex_str


def bin2dec(binary):
    """
    Binary to decimal conversion
    :param binary: Binary number
    :return: Decimal number
    """
    decimal, pow_num, n = 0, 0, 0
    while binary != 0:
        dec = binary % 10
        decimal = decimal + dec * pow(2, pow_num)
        binary = binary // 10
        pow_num += 1
    return decimal


def dec2bin(num):
    """
    Decimal to binary conversion
    :param num: Decimal number
    :return: Binary number
    """
    res = bin(num).replace("0b", "")
    if len(res) % 4 != 0:
        div = len(res) / 4
        div = int(div)
        counter = (4 * (div + 1)) - len(res)
        for _ in range(0, counter):
            res = '0' + res
    return res


def permute(k, arr, n):
    """
    Permute function to rearrange the bits
    :param k: input data
    :param arr: permutation table
    :param n: length
    :return: permutation of the initial data
    """
    permutation = ""
    for j in range(0, n):
        permutation = permutation + k[arr[j] - 1]
    return permutation


def shift_left(k, nth_shifts):
    """
    Shifting the bits towards left by nth shifts
    :param k: To shift value
    :param nth_shifts: quantity of shifts
    :return: Shifted value
    """
    s = ""
    for _ in range(nth_shifts):
        for j in range(1, len(k)):
            s = s + k[j]
        s = s + k[0]
        k = s
        s = ""
    return k


def xor(a, b):
    """
    Calculating xor of two strings of binary number a and b
    :param a: string
    :param b: string
    :return: Xor of a and b
    """
    ans = ""
    for j in range(len(a)):
        if a[j] == b[j]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans


# Table of Position of 64 bits at initial level: Initial Permutation Table
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

# Expansion D-box Table
exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1]

# Straight Permutation Table
per = [16, 7, 20, 21,
       29, 12, 28, 17,
       1, 15, 23, 26,
       5, 18, 31, 10,
       2, 8, 24, 14,
       32, 27, 3, 9,
       19, 13, 30, 6,
       22, 11, 4, 25]

# S-box Table
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Final Permutation Table
final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]


def encrypt(pt, rkb, rk):
    """
    Process DES algorithm
    :param pt: Input string
    :param rkb: RoundKeys in binary
    :param rk: RoundKeys in hexadecimal
    :return: Cipher text
    """
    pt = hex2bin(pt)

    # Initial Permutation
    pt = permute(pt, initial_perm, 64)
    # print("After initial permutation", bin2hex(pt))

    # Splitting
    left = pt[0:32]
    right = pt[32:64]

    for itr in range(0, 16):
        #  Expansion D-box: Expanding the 32 bits data into 48 bits
        right_expanded = permute(right, exp_d, 48)

        # XOR RoundKey[i] and right_expanded
        xor_x = xor(right_expanded, rkb[itr])

        # S-box: substituting the value from s-box table by calculating row and column
        sbox_str = ""
        for i in range(0, 8):
            row = bin2dec(int(xor_x[i * 6] + xor_x[i * 6 + 5]))
            col = bin2dec(int(xor_x[i * 6 + 1] + xor_x[i * 6 + 2] + xor_x[i * 6 + 3] + xor_x[i * 6 + 4]))
            val = sbox[i][row][col]
            sbox_str = sbox_str + dec2bin(val)

        # Straight D-box: After substituting rearranging the bits 
        sbox_str = permute(sbox_str, per, 32)

        # XOR left and sbox_str
        result = xor(left, sbox_str)
        left = result

        # Swapper
        if itr != 15:
            left, right = right, left
        # print("Round ", itr + 1, " ", bin2hex(left), " ", bin2hex(right), " ", rk[itr])

    # Combination
    combine = left + right

    # Final permutation: final rearranging of bits to get cipher text
    return permute(combine, final_perm, 64)


def get_round_keys(key):
    """
    Getting round keys for 16 rounds of the DES algorithm
    :param key: key in hexadecimal format to generate round keys
    :return: 16 round keys in binary and hexadecimal formats
    """
    # Key generation
    key = hex2bin(key)

    # --parity bit drop table
    key_p = [57, 49, 41, 33, 25, 17, 9,
             1, 58, 50, 42, 34, 26, 18,
             10, 2, 59, 51, 43, 35, 27,
             19, 11, 3, 60, 52, 44, 36,
             63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
             14, 6, 61, 53, 45, 37, 29,
             21, 13, 5, 28, 20, 12, 4]

    # getting 56 bit key from 64 bit using the parity bits
    key = permute(key, key_p, 56)

    # Number of bit shifts
    shift_table = [1, 1, 1, 2,
                   2, 2, 2, 2,
                   1, 2, 2, 2,
                   2, 2, 2, 1]

    # Key- Compression Table : Compression of key from 56 bits to 48 bits
    key_comp = [14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32]

    # Splitting
    left_key = key[0:28]
    right_key = key[28:56]

    _round_keys_b = []  # round_keys_b for RoundKeys in binary
    _round_keys_hex = []  # round_key_hex for RoundKeys in hexadecimal
    for p in range(0, 16):
        # Shifting the bits by nth shifts by checking from shift table
        left_key = shift_left(left_key, shift_table[p])
        right_key = shift_left(right_key, shift_table[p])

        # Combination of left and right string
        combine_str = left_key + right_key

        # Compression of key from 56 to 48 bits
        round_key = permute(combine_str, key_comp, 48)

        _round_keys_b.append(round_key)
        _round_keys_hex.append(bin2hex(round_key))

    return _round_keys_b, _round_keys_hex


def get_blocks(initial_message, chunk_size):
    """
    Breaking message into blocks of certain size
    :param initial_message: string we would like to break into chunks
    :param chunk_size: size of each chunk
    :return: chunks of the initial_message of the chunk_size length
    (the latter can be supplemented with zeros till the right length)
    """
    chunks = [initial_message[i:i + chunk_size] for i in range(0, len(initial_message), chunk_size)]
    chunks[-1] += "0" * (16 - len(chunks[-1]))

    return chunks


def encrypt_message(message_chunks, round_keys_binary, round_key_hexadecimal):
    """
    Encrypting message with DES algorithm
    :param message_chunks: initial text broken into chunks
    :param round_keys_binary: keys for each of th 16 rounds (binary)
    :param round_key_hexadecimal: keys for each of th 16 rounds (hexadecimal)
    :return: encrypted initial message
    """
    cipher_text = ""
    for message_chunk in message_chunks:
        cipher_text += bin2hex(encrypt(message_chunk, round_keys_binary, round_key_hexadecimal))

    return cipher_text


def decrypt_message(message_chunks, round_keys_binary, round_key_hexadecimal):
    """
    Decrypting message with DES algorithm
    :param message_chunks: chunks of the encrypted message
    :param round_keys_binary: keys for each of th 16 rounds (binary)
    :param round_key_hexadecimal: keys for each of th 16 rounds (hexadecimal)
    :return: decrypted message
    """
    rkb_rev = round_keys_binary[::-1]
    rk_rev = round_key_hexadecimal[::-1]

    plain_text = ""
    for message_chunk in message_chunks:
        plain_text += bin2hex(encrypt(message_chunk, rkb_rev, rk_rev))

    return plain_text


def encrypt_3des(key, input_chunks):
    """
    Decrypting message with 3DES algorithm
    :param key: key in hexadecimal format
    :param input_chunks: chunks of the input message
    :return: encrypted message
    """
    round_keys_b_1, round_key_hex_1 = get_round_keys(key[0:16])
    round_keys_b_2, round_key_hex_2 = get_round_keys(key[16:32])
    round_keys_b_3, round_key_hex_3 = get_round_keys(key[32:48])

    message = encrypt_message(input_chunks, round_keys_b_1, round_key_hex_1)
    message = decrypt_message(get_blocks(message, 16), round_keys_b_2, round_key_hex_2)
    message = encrypt_message(get_blocks(message, 16), round_keys_b_3, round_key_hex_3)

    return message


def decrypt_3des(key, cipher_chunks):
    """
    Decrypting message with 3DES algorithm
    :param key: key in hexadecimal format
    :param cipher_chunks: chunks of the encrypted message
    :return: decrypted message
    """
    round_keys_b_1, round_key_hex_1 = get_round_keys(key[0:16])
    round_keys_b_2, round_key_hex_2 = get_round_keys(key[16:32])
    round_keys_b_3, round_key_hex_3 = get_round_keys(key[32:48])

    message = decrypt_message(cipher_chunks, round_keys_b_3, round_key_hex_3)
    message = encrypt_message(get_blocks(message, 16), round_keys_b_2, round_key_hex_2)
    message = decrypt_message(get_blocks(message, 16), round_keys_b_1, round_key_hex_1)

    return message


if __name__ == "__main__":
    input_str = "123456ABCD132536ADC58932BBBBBBB438291AAAAAA"
    key_str = "AABB09182736CCDDFA5843098ECCD234198ACBDDCCBCDCBD"

    print("Plain Text: %s\n" % input_str)
    input_chunks = get_blocks(input_str, 16)

    print("Encryption...")
    encrypted_message = encrypt_3des(key_str, input_chunks)

    print("Cipher Text: %s\n" % encrypted_message)

    print("Decryption...")
    cipher_chunks = get_blocks(encrypted_message, 16)
    decrypted_message = decrypt_3des(key_str, cipher_chunks)

    print("Plain Text: %s\n" % decrypted_message)


