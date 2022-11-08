import numpy as np
import copy

# Global variables
b = 4
T = 10

s_box = np.array([
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16],
])

Rcon = np.array([
    [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
])

Rcon_transpose = np.transpose(Rcon)

# Variables you may change
cipher_key = np.array([
    [0x2b, 0x28, 0xab, 0x09],
    [0x7e, 0xae, 0xf7, 0xcf],
    [0x15, 0xd2, 0x15, 0x4f],
    [0x16, 0xa6, 0x88, 0x3c]
])

## Message you want to apply AES to
X = np.array([
    [0x32, 0x88, 0x31, 0xe0],
    [0x43, 0x5a, 0x31, 0x37],
    [0xf6, 0x30, 0x98, 0x07],
    [0xa8, 0x8d, 0xa2, 0x34]
])


# Functions to calculate AES
def print_hex(X):
    for i in range(len(X)):
        if i == 0:
            print("[", end="")
        else:
            print(" ", end="")
        for j in range(len(X[i])):
            if j != b-1:
                print(hex(X[i, j]), end=", ")
            elif i != b-1:
                print(hex(X[i, j]))
            else:
                print(hex(X[i, j]), "]")

def split_bytes(num):
    return num >> 4, num & 0xF

def shift_rows(X):
    for i in range(b):
        X[i] = np.roll(X[i], -i)

def sub_bytes(X):
    for i in range(b):
        for j in range(b):
            X[i][j] = s_box[split_bytes(X[i][j])]

def gmul(a, b):
    if b == 1:
        return a
    if b == 2:
        tmp = (a << 1) & 0xff
        if a < 128:
            return tmp
        return tmp ^ 0x1b
    if b == 3:
        return gmul(a, 2) ^ a

def mix_1_column(w, x, y, z):
    return [
        gmul(w, 2) ^ gmul(x, 3) ^ gmul(y, 1) ^ gmul(z, 1),
        gmul(w, 1) ^ gmul(x, 2) ^ gmul(y, 3) ^ gmul(z, 1),
        gmul(w, 1) ^ gmul(x, 1) ^ gmul(y, 2) ^ gmul(z, 3),
        gmul(w, 3) ^ gmul(x, 1) ^ gmul(y, 1) ^ gmul(z, 2)
    ]

def mix_colums(X):
    mixColum = []
    for j in range(b):
        mixColum = mix_1_column(X[0][j], X[1][j], X[2][j], X[3][j])
        for i in range(b):
            X[i, j] = mixColum[i]

def add_round_key(X, Y):
    return np.bitwise_xor(X, Y)

# Functions to modify round key
def print_col_hex(col):
    print("[", end=" ")
    for i in range(len(col) - 1):
        print(hex(col[i]), end = ", ")
    print(hex(col[i+1]), "]")

def get_column(X, j):
    return np.array([X[i, j] for i in range(b)])

def set_column(X, j, column):
    for i in range(b):
        X[i, j] = column[i]

def rot_word(column):
    return np.roll(column, -1)

def sub_bytes_1_column(column):
    for i in range(b):
        column[i] = s_box[split_bytes(column[i])]

def add_column(col1, col2):
    return np.bitwise_xor(col1, col2)

def get_new_round_key(round, former_round_key):

    new_round_key = np.arange(b*b)
    new_round_key = new_round_key.reshape((b, b))
    new_round_key = np.zeros_like(new_round_key)
    #print(new_round_key)

    #print("= Col init =")
    col = get_column(former_round_key, 3)
    #print_col_hex(col)

    #print("= Rot word =")
    col = rot_word(col)
    #print_col_hex(col)

    #print("= Subbyte =")
    sub_bytes_1_column(col)
    #print_col_hex(col)

    #print("= Col minus 4 =")
    col_minus_4 = get_column(former_round_key, 0)
    #print_col_hex(col_minus_4)

    #print("= XOR =")
    col = add_column(col, col_minus_4)
    col = add_column(col, Rcon_transpose[round])
    #print_col_hex(col)

    #print("= Add columns to new round key =")
    set_column(new_round_key, 0, col)
    #print_hex(new_round_key)

    for i in range(1, b):
        col = get_column(new_round_key, i - 1)
        col_minus_4 = get_column(former_round_key, i)
        col = add_column(col, col_minus_4)
        set_column(new_round_key, i, col)
    
    return new_round_key

# AES Encryption
def AES_encrypt(clearX, T):

    encryptedX = copy.deepcopy(clearX)
    former_round_key = copy.deepcopy(cipher_key)

    # Initial round
    #print("========= INITIAL ROUND ============")
    encryptedX = add_round_key(encryptedX, former_round_key)
    # print("> Encrypted X")
    # print_hex(encryptedX)

    # Rounds 0 to T - 1
    for round in range(0, T):

        #print("========= ROUND ", round + 1, " ============")

        # Create round key
        round_key = get_new_round_key(round, former_round_key)
        # print("> Key")
        # print_hex(round_key)

        # Sub Bytes
        sub_bytes(encryptedX)

        # Shift Rows
        shift_rows(encryptedX)
    
        # Mix Columns
        if (round != T - 1):
            mix_colums(encryptedX)

        # Add round Key
        encryptedX = add_round_key(encryptedX, round_key)

        # Rebase round key
        former_round_key = copy.deepcopy(round_key)
        
        # print("> Encrypted X")
        # print_hex(encryptedX)
    
    return encryptedX

def test_func_aes():
    round_key = np.array([
        [0xa0, 0x88, 0x23, 0x2a],
        [0xfa, 0x54, 0xa3, 0x6c],
        [0xfe, 0x2c, 0x39, 0x76],
        [0x17, 0xb1, 0x39, 0x05]
    ])
    print("= Init =")
    print_hex(X)

    print("= Sub Bytes =")
    sub_bytes(X)
    print_hex(X)

    print("= Shift Rows =")
    shift_rows(X)
    print_hex(X)

    print("= Mix Columns =")
    mix_colums(X)
    print_hex(X)

    print("= Add round Key =")
    X = add_round_key(X, round_key)
    print_hex(X)

def main():
    print("> Key:")
    print_hex(cipher_key)
    print("> cleared X")
    print_hex(X)
    print("encrypted X:")
    print_hex(AES_encrypt(X, T))

if __name__ == "__main__":
    # test_func_aes()
    main()