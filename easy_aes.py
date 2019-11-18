import aes

class easy_aes():
    def __init__(self):
        self.CIPHER = aes.aes(256)

    def encrypt(self, text, key):
        blocks = self._sub_divide(text, 16)
        if not blocks: return
        padding = (16 - len(blocks[-1]))
        blocks[-1] += padding * "="
        blocks.append(format(padding, "x")*16)

        key_hash = self._expand_key(key)

        encrypted_blocks = ""
        for block in blocks:
            for i in self.CIPHER.encrypt(str(key_hash), block):
                hex_val = hex(i)[2:]
                if len(hex_val) == 1: hex_val = "0" + hex_val
                encrypted_blocks += hex_val

        return encrypted_blocks

    def decrypt(self, cipher_text, key):
        blocks = self._sub_divide(cipher_text, 32)
        if not blocks: return

        key_hash = self._expand_key(key)

        plain_text = ""
        for block in blocks:
            cipher_block = []
            for h in self._sub_divide(block, 2):
                cipher_block.append(int(h, 16))

            plain_text += self.CIPHER.to_plain(self.CIPHER.decrypt(str(key_hash), cipher_block))
        return plain_text[:-16-int(plain_text[-1], 16)]
    
    def _sub_divide(self, data, index):
        return [data[i:i+index] for i in range(0, len(data), index)]
    
    def _expand_key(self, key):
        key_hash = 1
        for i, c in enumerate(key): key_hash += ord(c) << (8*i)
        while key_hash < 0xfffffffffffff:
            key_hash *= key_hash
        key_hash &= 0xfffffffffffff
    
        return key_hash

if __name__ == "__main__":
    # RUN DEMO
    cipher = easy_aes()

    KEY = "Tis but a scratch!"
    DATA = "A scratch?! your arm's off!"

    cipher_text = cipher.encrypt(DATA, KEY)
    print("CIPHER TEXT: " + cipher_text)

    plain_text = cipher.decrypt(cipher_text, KEY)
    print("\nPLAIN TEXT TEXT: " + plain_text)

