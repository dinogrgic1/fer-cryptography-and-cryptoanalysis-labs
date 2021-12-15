from random import choice
from core import decrypt, encrypt

__SUPPORTED_MODES = ['envelope', 'signature', 'seal']
__SUPPORTED_SYMETRIC = ['aes-128-ecb', 'aes-128-cbc', 'aes-192-ecb', 'aes-192-cbc', 'aes-256-ecb', 'aes-256-cbc', 'des3-128-ecb', 'des3-128-cbc', 'des3-192-ecb', 'des3-192-cbc']
__SUPPORTED_ASYMETRIC = ['1024', '2048', '3072', '4096']
__SUPPORTED_HASH = ['sha2-256', 'sha2-512', 'sha3-256', 'sha3-512']

messages = [
    'A cryptographic system should be secure even if everything about the system, except the key, is public knowledge. - Auguste Kerckhoffs',
    'Anyone who attempts to generate random numbers by deterministic means is, of course, living in a state of sin. - John von Neumann',
    'Random numbers should not be generated with a method chosen at random. - Donald Knuth',
    'Encryption works. Properly implemented strong crypto systems are one of the few things that you can rely on. Unfortunately, endpoint security is so terrifically weak that NSA can frequently find ways around it. - Edward Snowden',
    'The enemy knows the system. - Claude Shannon',
    'In God we trust. Everybody else we verify using PGP! - Tim Newsome'
]

def test_case(mode, symetric, asymetric, hash):
    print(f'==================================================== TEST CASE {mode} | {symetric} | rsa-{asymetric} | {hash} ====================================================')
    
    msg = choice(messages)
    print(f'Encypting message: {msg}')
    msg = msg.encode("UTF-8")

    args = {'mode': mode, 'sim': symetric, 'asim': asymetric, 'hash': hash, 'pubkey': f'keys/reciver-{asymetric}-pub.pem', 'privkey': f'keys/sender-{asymetric}-priv.pem', 'message': msg}
    data = encrypt(args)

    args['pubkey'] = f'keys/sender-{asymetric}-pub.pem'
    args['privkey'] = f'keys/reciver-{asymetric}-priv.pem'

    if mode == 'envelope':
        enc_message, enc_session_key, iv = data
        print(f'Envelope value: 0x{(enc_message + enc_session_key).hex()}')  

        args['message'] = enc_message
        args['session_key'] = enc_session_key
        args['iv'] = iv

        decrypted = decrypt(args)
        print(f'Decrypted message: {decrypted.decode()}')
        assert msg == decrypted

    elif mode == 'signature':
        message, signature = data
        print(f'Signature value: 0x{(message + signature).hex()}')

        args['message'] = message
        args['signature'] = signature

        signature_valid = decrypt(args)
        print(f'Hash is the same as decrypted hash with private key: {signature_valid}')
        assert signature_valid == True

    elif mode == 'seal':
        enc_message, enc_key, signature, iv = data
        print(f'Seal value: 0x{(enc_message + enc_key + signature).hex()}')

        args['message'] = enc_message
        args['session_key'] = enc_key
        args['signature'] = signature
        args['iv'] = iv

        decrypted, verify_signature = decrypt(args)
        print(f'Decrypted message: {decrypted.decode()}')
        print(f'Hash is the same as decrypted hash with private key: {verify_signature}')
        assert msg == decrypted
        assert verify_signature == True

    else:
        raise Exception('Wrong application mode')
    
    print('\n')


if __name__ == '__main__':
    for modes in __SUPPORTED_MODES:
        for simetric in __SUPPORTED_SYMETRIC:
            for asymetric in __SUPPORTED_ASYMETRIC:
                for hash in __SUPPORTED_HASH:
                    test_case(modes, simetric, asymetric, hash)