class AES128:
    __SBOX = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
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
    __INV__SBOX = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
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
                   0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
    __RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    __ROUNDS = 10
    __KEY_SIZE = 128

    key = b''
    round_key = []

    def __rotate_word_bytes(self, data):
        new_data = list(data)
        new_data = new_data[1:] + new_data[:1]
        return bytes(new_data)

    def __sub_word_bytes(self, data):
        new_data = []
        for t in list(data):
            new_data.append(self.__SBOX[t])
        return bytes(new_data)

    def __inv_sub_word_bytes(self, data):
        new_data = []
        for t in list(data):
            new_data.append(self.__INV__SBOX[t])
        return bytes(new_data)

    def __r_con_bytes(self, data, idx):
        new_data = list(data)
        new_data[0] = new_data[0] ^ self.__RCON[idx]
        return bytes(new_data)

    def xor_bytes(self, first, second):
        new = []
        for e, t in zip(first, second):
            new.append(e ^ t)
        return bytes(new)

    def __key_expand(self, key):
        exp = [0 for x in range(0, 44)]
        for i in range(0, 4):
            l = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]
            exp[i] = bytes(l)

        for i in range(4, 44):
            temp = exp[i - 1]
            if(i % 4 == 0):
                temp = self.__rotate_word_bytes(temp)
                temp = self.__sub_word_bytes(temp)
                temp = self.__r_con_bytes(temp, (i-1)//4)
            exp[i] = self.xor_bytes(exp[i - 4], temp)

        for i in range(0, len(exp), 4):
            self.round_key.append(exp[i] + exp[i+1] + exp[i+2] + exp[i+3])

    def __shift_rows_bytes(self, data):
        f1 = data[0:1] + data[5:6] + data[10:11] + data[15:16]
        f2 = data[4:5] + data[9:10] + data[14:15] + data[3:4]
        f3 = data[8:9] + data[13:14] + data[2:3] + data[7:8]
        f4 = data[12:13] + data[1:2] + data[6:7] + data[11:12]
        return f1 + f2 + f3 + f4

    def __inv_shift_rows_bytes(self, data):
        f1 = data[0:1] + data[13:14] + data[10:11] + data[7:8]
        f2 = data[4:5] + data[1:2] + data[14:15] + data[11:12]
        f3 = data[8:9] + data[5:6] + data[2:3] + data[15:16]
        f4 = data[12:13] + data[9:10] + data[6:7] + data[3:4]
        return f1 + f2 + f3 + f4

    def _gf2n_multiply(self, a, b):
        overflow = 0x100
        modulus = 0x11B

        sum = 0
        while (b > 0):
            if (b & 1):
                sum = sum ^ a
            b = b >> 1
            a = a << 1
            if (a & overflow):
                a = a ^ modulus

        return sum

    def __galaois_mul_word(self, data):
        s0 = self._gf2n_multiply(0x02, int(data[0:1].hex(), 16))
        s1 = self._gf2n_multiply(0x03, int(data[1:2].hex(), 16))
        a = s0 ^ s1
        b = int(data[2:3].hex(), 16) ^ int(data[3:4].hex(), 16)
        f1 = (a ^ b).to_bytes(1, byteorder='big')

        s1 = self._gf2n_multiply(0x02, int(data[1:2].hex(), 16))
        s2 = self._gf2n_multiply(0x03, int(data[2:3].hex(), 16))
        a = int(data[0:1].hex(), 16) ^ s1
        b = s2 ^ int(data[3:4].hex(), 16)
        f2 = (a ^ b).to_bytes(1, byteorder='big')

        s2 = self._gf2n_multiply(0x02, int(data[2:3].hex(), 16))
        s3 = self._gf2n_multiply(0x03, int(data[3:4].hex(), 16))
        a = int(data[0:1].hex(), 16) ^ int(data[1:2].hex(), 16)
        b = s2 ^ s3
        f3 = (a ^ b).to_bytes(1, byteorder='big')

        s0 = self._gf2n_multiply(0x03, int(data[0:1].hex(), 16))
        s3 = self._gf2n_multiply(0x02, int(data[3:4].hex(), 16))
        a = s0 ^ int(data[1:2].hex(), 16)
        b = s3 ^ int(data[2:3].hex(), 16)
        f4 = (a ^ b).to_bytes(1, byteorder='big')

        return f1 + f2 + f3 + f4

    def __inv_galaois_mul_word(self, data):
        s0 = self._gf2n_multiply(0x0e, int(data[0:1].hex(), 16))
        s1 = self._gf2n_multiply(0x0b, int(data[1:2].hex(), 16))
        s2 = self._gf2n_multiply(0x0d, int(data[2:3].hex(), 16))
        s3 = self._gf2n_multiply(0x09, int(data[3:4].hex(), 16))
        a = s0 ^ s1
        b = s2 ^ s3
        f1 = (a ^ b).to_bytes(1, byteorder='big')

        s0 = self._gf2n_multiply(0x09, int(data[0:1].hex(), 16))
        s1 = self._gf2n_multiply(0x0e, int(data[1:2].hex(), 16))
        s2 = self._gf2n_multiply(0x0b, int(data[2:3].hex(), 16))
        s3 = self._gf2n_multiply(0x0d, int(data[3:4].hex(), 16))
        a = s0 ^ s1
        b = s2 ^ s3
        f2 = (a ^ b).to_bytes(1, byteorder='big')

        s0 = self._gf2n_multiply(0x0d, int(data[0:1].hex(), 16))
        s1 = self._gf2n_multiply(0x09, int(data[1:2].hex(), 16))
        s2 = self._gf2n_multiply(0x0e, int(data[2:3].hex(), 16))
        s3 = self._gf2n_multiply(0x0b, int(data[3:4].hex(), 16))
        a = s0 ^ s1
        b = s2 ^ s3
        f3 = (a ^ b).to_bytes(1, byteorder='big')

        s0 = self._gf2n_multiply(0x0b, int(data[0:1].hex(), 16))
        s1 = self._gf2n_multiply(0x0d, int(data[1:2].hex(), 16))
        s2 = self._gf2n_multiply(0x09, int(data[2:3].hex(), 16))
        s3 = self._gf2n_multiply(0x0e, int(data[3:4].hex(), 16))
        a = s0 ^ s1
        b = s2 ^ s3
        f4 = (a ^ b).to_bytes(1, byteorder='big')

        return f1 + f2 + f3 + f4

    def __mult_bytes(self, data, func):
        f1 = func(data[0:4])
        f2 = func(data[4:8])
        f3 = func(data[8:12])
        f4 = func(data[12:16])
        return f1 + f2 + f3 + f4

    def __init__(self, key: bytes):
        if len(key) * 8 != 128:
            raise Exception('Wrong key size.')

        # Expand Key
        self.__key_expand(key)
        self.key = key

    def encrypt(self, plaintext):
        if len(plaintext) * 8 != 128:
            raise Exception('Wrong data size.')

        data = self.xor_bytes(self.round_key[0], plaintext)
        for i in range(0, self.__ROUNDS - 1):
            data = self.__sub_word_bytes(data)
            data = self.__shift_rows_bytes(data)
            data = self.__mult_bytes(data, self.__galaois_mul_word)
            data = self.xor_bytes(self.round_key[i+1], data)

        data = self.__sub_word_bytes(data)
        data = self.__shift_rows_bytes(data)
        data = self.xor_bytes(self.round_key[10], data)
        return data

    def decrypt(self, cipher):
        data = self.xor_bytes(self.round_key[10], cipher)
        data = self.__inv_shift_rows_bytes(data)
        data = self.__inv_sub_word_bytes(data)

        for i in range(self.__ROUNDS - 1, 0, -1):
            data = self.xor_bytes(self.round_key[i], data)
            data = self.__mult_bytes(data, self.__inv_galaois_mul_word)
            data = self.__inv_shift_rows_bytes(data)
            data = self.__inv_sub_word_bytes(data)
        
        data = self.xor_bytes(self.round_key[0], data)
        return data

class AES_ECB:
    AES = ''

    def __init__(self, AES):
        self.AES = AES

    def __pad(self, data):
        while len(data.hex()) != 32:
            data += b'0'
        return data

    def encrypt_text(self, text):
        text_bytes = bytes(text, 'utf-8')

        text_arr = []
        for i in range(0, len(text_bytes), 16):
            to_append = text_bytes[i:i+16]
            if len(to_append.hex()) < 32:
                to_append = self.__pad(to_append)
            text_arr.append(to_append)

        encrypted = []
        for t in text_arr:
            encrypted.append(self.AES.encrypt(t))
        
        text = b''
        for e in encrypted:
            text += e
        return text

    def decrypt_text(self, encrpyted_text):
        text_arr = []
        for i in range(0, len(encrpyted_text), 16):
            to_append = encrpyted_text[i:i+16]
            if len(to_append.hex()) < 32:
                to_append = self.__pad(to_append)
            text_arr.append(to_append)

        encrypted = []
        for t in text_arr:
            encrypted.append(self.AES.decrypt(t))
        
        text = ''
        for e in encrypted:
            text += e.decode('utf-8').rstrip('0')
        return text

class AES_CBC:
    AES = ''

    def __init__(self, AES, IV):
        self.AES = AES
        self.IV = IV

    def __pad(self, data):
        while len(data.hex()) != 32:
            data += b'0'
        return data

    def encrypt_text(self, text):
        text_bytes = bytes(text, 'utf-8')

        text_arr = []
        for i in range(0, len(text_bytes), 16):
            to_append = text_bytes[i:i+16]
            if len(to_append.hex()) < 32:
                to_append = self.__pad(to_append)
            text_arr.append(to_append)

        encrypted = []
        for i in range(0, len(text_arr)):
            if i == 0:
                iv_xor_ct = self.AES.xor_bytes(list(text_arr[i]), list(self.IV))
            else:
                iv_xor_ct = self.AES.xor_bytes(list(text_arr[i]), encrypted[i-1])
            encrypted.append(self.AES.encrypt(iv_xor_ct))
        
        text = b''
        for e in encrypted:
            text += e
        return text

    def decrypt_text(self, encrpyted_text):
        text_arr = []
        for i in range(0, len(encrpyted_text), 16):
            to_append = encrpyted_text[i:i+16]
            if len(to_append.hex()) < 32:
                to_append = self.__pad(to_append)
            text_arr.append(to_append)

        decrypted = [0 for i in range(len(text_arr))]
        for i in range(len(text_arr) - 1, -1, -1):
            decrypted[i] = self.AES.decrypt(text_arr[i])
            if i == 0:
                iv_xor_ct = self.AES.xor_bytes(list(decrypted[i]), list(self.IV))
            else:
                iv_xor_ct = self.AES.xor_bytes(list(text_arr[i - 1]), decrypted[i])
            decrypted[i] = iv_xor_ct
            

        text = ''
        for e in decrypted:
            text += e.decode().rstrip('0')
        return text
        

