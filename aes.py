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

# ADVANCED ENCRYPTION STANDARD
# by Gecko
# Description of steps: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

class aes():
    """
    The AES class contains all of the necessary methods for encrypting data
    in the advanced encryption standard. It supports 128, 192, and 256 bit protocols.

    encrypt [key] [plaintext]
        key: 16 byte string used to generate the round keys
            and encrypt the cipher for later decryption

        data: 16 byte string processed with the key to output
            encrypted data
        
        RETURNS: a 16 element long array of integers
    
    decrypt [key] [ciphertext]
        key: 16 byte string used to generate the round keys
            and encrypt the cipher for later decryption
        
        data: 16 long array of integer data holding the encrypted
            cipher text.
        
        RETURNS: 16 element long array of integers
    
    to_hex [integer_array]
        integer_array: an array of integers any length

        RETURNS: a hex representation of the input data
    
    to_plain [integer_array]
        integer_array: an array of integers any length

        RETURNS: plain text characters of the input data
    """

    def __init__(self, bit):
        if bit == 128:
            self.ROUNDS = 10
        elif bit == 192:
            self.ROUNDS = 12
        elif bit == 256:
            self.ROUNDS = 14
        else:
            raise Exception("Bit amount must be 128, 192, or 256")

    def encrypt(self, key, data):
        """
         ENCRYPTION OUTLINE
        
         AddRoundKey
          ______________
         / Repeat Nr-1
         |______________
         | SubBytes
         | ShiftRows
         | MixColumns
         | AddRoundKey
         \______________
        
         SubBytes
         ShiftRows
         AddRoundKey
        
         Cipher text (outputted in an integer array)
        """

        # Divide input text into a state matrix
        # (4x4) hex data
        self.state = []
        for k in self._subdivide_string(data, 4):
            state_line = []
            for sk in k: state_line.append(ord(sk))
            self.state.append(state_line)

        self._expand_key(key, self.ROUNDS)

        # ADD ROUND KEY
        # Each byte of the state is combined with a block of the round key using bitwise xor.
        self.state = self._add_round_key(self.state, self.round_keys[0], True)

        # ROUND LOOP
        # The amount of rounds to loop depends on AES mode, 128-bit, 192-bit, 
        # or 256-bit (currently not supported)
        for round_number in range(self.ROUNDS):

            # SUBSTITUTE BYTES
            # a non-linear substitution step where each byte is replaced with another according to a 
            # lookup table.
            self._sub_bytes(self.state)

            # SHIFT ROWS
            # a transposition step where the last three rows of the state are shifted cyclically a 
            # certain number of steps.
            self._shift_rows(self.state)

            if round_number != self.ROUNDS-1: # Last Round does perform MixColumns
                # MIX COLUMNS
                # a linear mixing operation which operates on the columns of the state, combining
                # the four bytes in each column.
                self._mix_columns(self.state)

            # Add Round key (stated above)
            self.state = self._add_round_key(self.state, self.round_keys[round_number+1])

        return self._output(self.state)


    def decrypt(self, key, data):
        """
         DECRYPTION OUTLINE
        
         AddRoundKey
          ______________
         / Repeat Nr-1
         |______________
         | InvMixColumns
         | InvShiftRows
         | InvSubBytes
         | AddRoundKey
         \______________
        
         InvShiftRows
         InvSubBytes
         AddRoundKey
        
         Plain text (string data)
        """

        # Divide input text into a state matrix
        # (4x4) hex data
        self.state = []
        for k in self._subdivide_string(data, 4):
            state_line = []
            for sk in k: state_line.append(sk)
            self.state.append(state_line)
        
        self.state = self._swap_xy(self.state)

        self._expand_key(key, self.ROUNDS)

        # ADD ROUND KEY
        # Each byte of the state is combined with a block of the round key using bitwise xor.
        self.state = self._add_round_key(self.state, self.round_keys[self.ROUNDS])

        # ROUND LOOP
        # The amount of rounds to loop depends on AES mode, 128-bit, 192-bit, 
        # or 256-bit (currently not supported)
        for round_number in range(self.ROUNDS):
            if round_number != 0:
                # MIX COLUMNS
                self.state = self._inv_mix_columns(self.state)

            # INVERSE SHIFT ROWS
            self._inv_shift_rows(self.state)

            # INVERSE SUBSTITUTE BYTES
            self._inv_sub_bytes(self.state)

            # ADD ROUND KEY
            self.state = self._add_round_key(self.state, self.round_keys[self.ROUNDS-round_number-1])

        return self._output(self.state)
    
    def to_hex(self, int_array=[]):
        r = ""
        for i in int_array: r += hex(i)[2:].upper() + " "
        return r
    
    def to_plain(self, int_array=[]):
        r = ""
        for i in int_array: r += chr(i)
        return r

    def _expand_key(self, key, ROUNDS):
        # 10 rounds: 128 bit
        # 12 rounds: 192 bit
        # 14 rounds: 256 bit

        # Divides input key into a key matrix
        # (4x4) hex data
        round_key = []
        for k in self._subdivide_string(key, 4):
            hex_chunk = []
            for h in k: hex_chunk.append(ord(h))
            round_key.append(hex_chunk)
        
        # Key Expansion
        # round keys are derived from the cipher key using Rijndael's key schedule. AES requires 
        # a separate 128-bit round key block for each round plus one more.
        self.round_keys = []
        round_key_sub = [[],[],[],[]]
        rci = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5] # Rounding constant
        for i in range(ROUNDS+1):
            self.round_keys.append(round_key+[])

            gw3 = round_key[3]+[]
            gw3.append(gw3.pop(0))
            for idx, c in enumerate(gw3): gw3[idx] = self._s_box_swap(c, self.s_box)
            if i+1 == 1: gw3[0] ^= 1
            elif i+1 > 1 and 0x80 > rci[i-1]: gw3[0] ^= 2*rci[i-1]
            else: gw3[0] ^= (2*rci[i-1] ^ 0x1b) % 256

            round_key_sub[0] = self._list_xor(round_key[0], gw3)
            round_key_sub[1] = self._list_xor(round_key_sub[0], round_key[1])
            round_key_sub[2] = self._list_xor(round_key_sub[1], round_key[2])
            round_key_sub[3] = self._list_xor(round_key_sub[2], round_key[3])

            round_key = round_key_sub

    def _add_round_key(self, state, round_key, _swap_xy=False):
        added_state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
        for x in range(4):
            for y in range(4):
                if _swap_xy: state_val = state[x][y]
                else: state_val = state[y][x]
                added_state[y][x] = state_val ^ round_key[x][y]
        state = added_state
        return state

    def _sub_bytes(self, state):
        for x in range(4):
            for y in range(4):
                state[x][y] = self._s_box_swap(state[x][y], self.s_box)
        return state

    def _inv_sub_bytes(self, state):
        for x in range(4):
            for y in range(4):
                state[x][y] = self._s_box_swap(state[x][y], self.inv_s_box)
        return state

    def _shift_rows(self, state):
        for i in range(4):
            for s in range(i):
                state[i].append(state[i].pop(0))
        return state

    def _inv_shift_rows(self, state):
        for i in range(4):
            for s in range(i):
                state[i].insert(0, state[i].pop(-1))
        return state

    def _mix_columns(self, state):
        columns = []
        mixed_chunk = []
        for ci in range(4):
            mixed_column = []
            mask = [2, 3, 1, 1]

            for m in range(4):
                net = 0
                for c in range(4):
                    net ^= self._finite_multiply(state[c][ci], mask[c])
                mask.insert(0, mask.pop())

                mixed_column.append(net)
                
            for r in range(4):
                state[r][ci] = mixed_column[r]
        
        return state

    def _inv_mix_columns(self, state):
        columns = []
        mixed_chunk = []
        for ci in range(4):
            mixed_column = []
            mask = [14, 11, 13, 9]

            for m in range(4):
                net = 0
                for c in range(4):
                    net ^= self._finite_multiply(state[c][ci], mask[c])
                mask.insert(0, mask.pop())

                mixed_column.append(net)
                
            for r in range(4):
                state[r][ci] = mixed_column[r]
        
        return state

    # Split strings into chunks
    def _subdivide_string(self, string, chars):
        return [string[i:i+chars] for i in range(0, len(string), chars)]

    # Multiplication in finite field
    def _finite_multiply(self, a, b):
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
    def _list_xor(self, a, b):
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
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    inv_s_box = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    ]

    def _s_box_swap(self, char, s_box):
        if type(char) == int: uni = char
        else: uni = ord(char)
        if uni <= 256: return s_box[16*(uni >> 4) + (uni & 0x0F)]
        else: return uni

    def _swap_xy(self, state):
        temp_state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
        for x in range(4):
            for y in range(4):
                temp_state[y][x] = state[x][y]
        state = temp_state
        return state
    
    def _output(self, a):
        r = []
        for y in range(4):
            for x in range(4):
                r.append(a[x][y])
        return r



if __name__ == "__main__":
    # RUN DEMO
    cipher = aes(256)

    KEY =   "Super secret key"
    DATA =  "Secret data shhh"

    cipher_text = cipher.encrypt(KEY, DATA)
    cipher_text_hex = cipher.to_hex(cipher_text)
    print("ENCRYPTED CIPHER TEXT: {}".format(cipher_text_hex))


    plain_text = cipher.decrypt(KEY, cipher_text)
    plain_text_ascii = cipher.to_plain(plain_text)
    print("DECRYPTED PLAIN TEXT:  \"{}\"".format(plain_text_ascii))