from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA3_256, SHA3_512, SHA256, SHA512
from Crypto.Signature import pkcs1_15

def sim_algorithm_choice(sim, key=None, iv=None):
    if sim[:3] == 'aes':
        key_size = int(sim[4:7]) // 8
        
        if key == None:
            key = get_random_bytes(key_size)

        if sim[-3:] == 'ecb':
            return AES.new(key, mode=AES.MODE_ECB), key
        else:
            return AES.new(key, IV=iv, mode=AES.MODE_CBC), key

    elif sim[:4] == 'des3':
        key_size = int(sim[5:8]) // 8

        if key == None:
            key = get_random_bytes(key_size)

        if sim[-3:] == 'ecb':
            return DES3.new(key, DES3.MODE_ECB), key
        else:
            return DES3.new(key, IV=iv, mode=DES3.MODE_CBC), key
    else:
        raise Exception('Symetric crypto algorithm not supported')

def sim_encrypt(sim, key=None, msg=None):
    if sim[-3:] == 'ecb' and sim[:3] == 'aes':
        algorithm, key = sim_algorithm_choice(sim)
        msg = pad(msg, AES.block_size)
        return algorithm.encrypt(msg), key, None

    elif sim[-3:] == 'cbc' and sim[:3] == 'aes':
        algorithm, key = sim_algorithm_choice(sim)
        return algorithm.encrypt(pad(msg, AES.block_size)), key, algorithm.iv
    
    elif sim[-3:] == 'ecb' and sim[:4] == 'des3':
        algorithm, key = sim_algorithm_choice(sim)
        return algorithm.encrypt(pad(msg, DES3.block_size)), key, None
    
    elif sim[-3:] == 'cbc' and sim[:4] == 'des3':
        algorithm, key = sim_algorithm_choice(sim)
        return algorithm.encrypt(pad(msg, DES3.block_size)), key, algorithm.iv
    else:
        raise Exception('Symetric crypto algorithm not supported')

def sim_decrypt(sim, key, iv, msg):
    if sim[-3:] == 'ecb' and sim[:3] == 'aes':
        algorithm, key = sim_algorithm_choice(sim, key)
        return unpad(algorithm.decrypt(msg), AES.block_size)
    
    elif sim[-3:] == 'cbc' and sim[:3] == 'aes':
        algorithm, key = sim_algorithm_choice(sim, key, iv)
        return unpad(algorithm.decrypt(msg), AES.block_size)
    
    elif sim[-3:] == 'ecb' and sim[:4] == 'des3':
        algorithm, key = sim_algorithm_choice(sim, key)
        return unpad(algorithm.decrypt(msg), DES3.block_size)
    
    elif sim[-3:] == 'cbc' and sim[:4] == 'des3':
        algorithm, key = sim_algorithm_choice(sim, key, iv)
        return unpad(algorithm.decrypt(msg), DES3.block_size)
    
    else:
        raise Exception('Symetric crypto algorithm not supported')

def hash_algorithm(hash, msg):
    if hash == 'sha2-256':
        return SHA256.new(msg)
    
    elif hash == 'sha2-512':
        return SHA512.new(msg)
   
    elif hash == 'sha3-256':
        return SHA3_256.new().update(msg)
    
    elif hash == 'sha3-512':
        return SHA3_512.new().update(msg)
    
    else:
        raise Exception('Hash algorithm not supported')

# E(message, key) E_RSA(key, pubkey_B)
def envelope(args, message):
    enc_message, key, iv = sim_encrypt(args['sim'], msg=message)
    recipient_key = RSA.import_key(open(args['pubkey']).read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(key)
    return (enc_message, enc_session_key, iv)

# messsage E_RSA(hash(message), private_B)
def signature(args, message):
    key = RSA.import_key(open(args['privkey']).read())
    hash = hash_algorithm(args['hash'], message)
    signature = pkcs1_15.new(key).sign(hash)
    return (message, signature)
    
def encrypt(args):
    mode = args['mode']
    message = args['message']

    if mode == 'envelope':
        return envelope(args, message)
    
    elif mode == 'signature':
        return signature(args, message)

    # signature(envelope(message))
    elif mode == 'seal':
        enc_msg, enc_key, iv = envelope(args, message)
        message, sig = signature(args, enc_msg + enc_key)
        return (enc_msg, enc_key, sig, iv)
    
    else:
        raise Exception('Program mode not supported')

def decrypt(args):
    mode = args['mode']
    if mode == 'envelope':
        private_key = RSA.import_key(open(args['privkey']).read())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(args['session_key'])
        decrypted = sim_decrypt(args['sim'], session_key, args['iv'], args['message'])
        return decrypted

    elif mode == 'signature':
        key = RSA.import_key(open(args['pubkey']).read())
        hash = hash_algorithm(args['hash'], args['message'])
        try:
            pkcs1_15.new(key).verify(hash, args['signature'])
            return True
        except (ValueError, TypeError):
            return False
    
    elif mode == 'seal':

        key = RSA.import_key(open(args['pubkey']).read())
        hash = hash_algorithm(args['hash'], args['message'] + args['session_key'])

        try:
            pkcs1_15.new(key).verify(hash, args['signature'])
            verify_signature = True
        except (ValueError, TypeError):
            verify_signature = False

        private_key = RSA.import_key(open(args['privkey']).read())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(args['session_key'])
        decrypted = sim_decrypt(args['sim'], session_key, args['iv'], args['message'])

        return (decrypted, verify_signature) 
    
    else:
        raise Exception('Program mode not supported')