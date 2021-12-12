from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA3_256, SHA3_512, SHA256, SHA512

def sim_algorithm_choice_and_encrypt(sim, key=None, msg=b'Example'):
    if key == None:
        print('[WRN] Key for symetric cryptosystem not provided. Generating random key.')
        key = get_random_bytes(16)
        print(f'[WRN] Generated key: {key}')

    if sim == 'aes-ecb':
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(msg, AES.block_size)), key, None
    
    elif sim == 'aes-cbc':
        cipher = AES.new(key, AES.MODE_CBC)
        return cipher.encrypt(pad(msg, AES.block_size)), key, cipher.iv
    
    elif sim == 'des3-ecb':
        cipher = DES3.new(key, DES3.MODE_ECB)
        return cipher.encrypt(pad(msg, DES3.block_size)), key, None
    
    elif sim == 'des3-cbc':
        cipher = DES3.new(key, DES3.MODE_CBC)
        return cipher.encrypt(pad(msg, DES3.block_size)), key, cipher.iv
    
    else:
        raise Exception('Symetric crypto algorithm not supported')

def hash_algorithm_choice_and_encrypt(hash, msg='Dobar dan!'):
    if hash == 'sha2-256':
        return SHA256.new(msg).digest()
    elif hash == 'sha2-512':
        return SHA512.new(msg).digest()
    elif hash == 'sha3-256':
        return SHA3_256.new().update(msg).digest()
    elif hash == 'sha3-512':
        return SHA3_512.new().update(msg).digest()
    else:
        raise Exception('Hash algorithm not supported')

def mode_select(args):
    
    mode = args.mode

    if mode == 'envelope':
        enc_message, key, iv = sim_algorithm_choice_and_encrypt(args.sim, key=None, msg=b'Dobar dan!')
        recipient_key = RSA.import_key(open(args.pubkey).read())
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(key)
        print(enc_message)
        print(enc_session_key)

    elif mode == 'signature':

        hash = hash_algorithm_choice_and_encrypt(args.hash, b'Dobar dan')
        print(hash)

        sender_key = RSA.import_key(open(args.privkey).read())
        cipher_rsa = PKCS1_OAEP.new(sender_key)
        hash_encrypted = cipher_rsa.encrypt(hash)
        print(b'Dobar dan')
        print(hash_encrypted)

    elif mode == 'seal':
        ciphertext, key, iv = sim_algorithm_choice_and_encrypt(args.sim, key=None, msg=b'Dobar dan!')
        recipient_key = RSA.import_key(open(args.pubkey).read())
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(key)
        print(ciphertext)
        print(enc_session_key)

        hash = hash_algorithm_choice_and_encrypt(args.hash, b'Dobar dan')
        print(hash)

        sender_key = RSA.import_key(open(args.privkey).read())
        cipher_rsa = PKCS1_OAEP.new(sender_key)
        hash_encrypted = cipher_rsa.encrypt(hash)
        print(b'Dobar dan')
        print(hash_encrypted)

    else:
        raise Exception('Program mode not supported')