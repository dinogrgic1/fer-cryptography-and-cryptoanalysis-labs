# 0036516270 -- ECB I CBC
from AES import AES128, AES_ECB, AES_CBC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

if __name__ == '__main__':
    
    key = get_random_bytes(16)
    data = get_random_bytes(16)

    print(f'Encypting text {data.hex()} with key {key.hex()}')
    aes = AES128(key)
    cipher = aes.encrypt(data)

    print(f'Encypted value: {cipher.hex()}')
    print(f'Decrypting text {cipher.hex()} with key {key.hex()}')
    plaintext = aes.decrypt(cipher)
    print(f'Decrypted value: {plaintext.hex()}')

    iv = bytes.fromhex('00000000000000000000000000000000')
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    print(cipher)
    print(ciphertext)
    assert cipher == ciphertext

    print('\n==========================\n')
    text = 'The NSA lived by its motto: Everything is possible. The impossible just takes longer.'
    print(f'Encypting text {text} with key {key.hex()} in mode ECB')
    aes_cbc = AES_ECB(AES128(key))
    encrypted_text = aes_cbc.encrypt_text(text)
    print(f'Encypted text: {encrypted_text.hex()}')
    decrtpyted_text = aes_cbc.decrypt_text(encrypted_text)
    print(f'Decrypted text: {decrtpyted_text}')

    print('\n==========================\n')
    iv = get_random_bytes(16)
    print(f'Encypting text {text} with key {key.hex()} in mode CBC with IV {iv.hex()}')
    aes_cbc = AES_CBC(AES128(key), iv)
    encrypted_text = aes_cbc.encrypt_text(text)
    print(f'Encypted text: {encrypted_text.hex()}')
    decrtpyted_text = aes_cbc.decrypt_text(encrypted_text)
    print(f'Decrypted text: {decrtpyted_text}')