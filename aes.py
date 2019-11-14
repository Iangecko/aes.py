#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Ian
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Description of steps: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
# AES ENCRYPTION (Decryption coming soon)
# by Gecko

text = "Two One Nine Two"
key = "Thats my Kung Fu"

ROUNDS = 10
# 10 rounds: 128 bit keys
# 12 rounds: 192 bit keys
# 14 rounds: 256 bit keys (Not supported yet)





# Split strings into chunks
def subdivide_string(string, chars):
    return [string[i:i+chars] for i in range(0, len(string), chars)]

# Multiplication in finite field
def finite_multiply(a, b):
    reduction = 0b100011011 << 7
    b = b << 7
    p = 0
    for i in range(8):
        if a & (128 >> i):
            p ^= b

        if p & (256*128 >> i):
            p ^= reduction
        b = b >> 1

        reduction = reduction >> 1
    return p

# Exclusive or function
def list_xor(a, b):
    r = a+[]
    for i in range(len(a)):
        r[i] = (r[i] ^ b[i])
    return r

# S_Box lookup and swap function
s_box = [
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

def s_box_swap(char):
    if type(char) == int: uni = char
    else: uni = ord(char)
    if uni <= 256: return s_box[16*(uni >> 4) + (uni & 0x0F)]
    else: return uni

# Display function
def print_2D_hex(a, separate_lines = True):
    for y in range(4):
        for x in range(4):
            print(hex(a[x][y])[2:].upper(), end=" ")
        if separate_lines: print()
    print()





# Key Scheduler
# round keys are derived from the cipher key using Rijndael's key schedule. AES requires 
# a separate 128-bit round key block for each round plus one more.
def key_expansion(rounds, round_key):
    round_keys = []
    round_key_sub = [[],[],[],[]]
    rci = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5]
    for i in range(ROUNDS+1):
        round_keys.append(round_key+[])

        gw3 = round_key[3]+[]
        gw3.append(gw3.pop(0))
        for idx, c in enumerate(gw3): gw3[idx] = s_box_swap(c)
        if i+1 == 1: gw3[0] ^= 1
        elif i+1 > 1 and 0x80 > rci[i-1]: gw3[0] ^= 2*rci[i-1]
        else: gw3[0] ^= (2*rci[i-1] ^ 0x1b) % 256

        round_key_sub[0] = list_xor(round_key[0], gw3)
        round_key_sub[1] = list_xor(round_key_sub[0], round_key[1])
        round_key_sub[2] = list_xor(round_key_sub[1], round_key[2])
        round_key_sub[3] = list_xor(round_key_sub[2], round_key[3])

        round_key = round_key_sub

    return round_keys

def add_round_key(state, round_key, swap_xy=False):
    added_state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    for x in range(4):
        for y in range(4):
            if swap_xy: state_val = state[x][y]
            else: state_val = state[y][x]
            added_state[y][x] = state_val ^ round_key[x][y]
    state = added_state
    return state

def sub_bytes(state):
    for x in range(4):
        for y in range(4):
            state[x][y] = s_box_swap(state[x][y])
    return state

def shift_rows(state):
    for i in range(4):
        for s in range(i):
            state[i].append(state[i].pop(0))
    return state

def mix_columns(state):
    columns = []
    mixed_chunk = []
    for ci in range(4):
        mixed_column = []
        mask = [2, 3, 1, 1]

        for m in range(4):
            net = 0
            for c in range(4):
                net ^= finite_multiply(state[c][ci], mask[c])
            mask.insert(0, mask.pop())

            mixed_column.append(net)
            
        for r in range(4):
            state[r][ci] = mixed_column[r]
    
    return state





# Divides input key into a key matrix
# (4x4) hex data
round_key = []
for k in subdivide_string(key, 4):
    hex_chunk = []
    for h in k: hex_chunk.append(ord(h))

    round_key.append(hex_chunk)

# Divide input text into a state matrix
# (4x4) hex data
state = []
for k in subdivide_string(text, 4):
    state_line = []
    for sk in k: state_line.append(ord(sk))

    state.append(state_line)





# Key Expansion
# round keys are derived from the cipher key using Rijndael's key schedule. 
# AES requires a separate 128-bit round key block for each round plus one more.
round_keys = key_expansion(state, round_key)

# Add Round Key
# Each byte of the state is combined with a block of the round key using bitwise xor.
state = add_round_key(state, round_keys[0], True)

# Round loop
# The amount of rounds to loop depends on AES mode, 128-bit, 192-bit, 
# or 256-bit (currently not supported)
for round_number in range(ROUNDS):

    # Substitute Bytes
    # a non-linear substitution step where each byte is replaced with another according to a 
    # lookup table.
    sub_bytes(state)

    # Shift Rows
    # a transposition step where the last three rows of the state are shifted cyclically a 
    # certain number of steps.
    shift_rows(state)

    if round_number != ROUNDS-1: # Last Round does perform MixColumns
        # Mix Columns
        # a linear mixing operation which operates on the columns of the state, combining
        # the four bytes in each column.
        mix_columns(state)

    # Add Round key (stated above)
    state = add_round_key(state, round_keys[round_number+1])



# Print final state
print_2D_hex(state, False)