import argparse
from core import encrypt

__SUPPORTED_MODES = ['envelope', 'signature', 'seal']
__SUPPORTED_SYMETRIC = ['aes-128-ecb', 'aes-128-cbc', 'aes-192-ecb', 'aes-192-cbc', 'aes-256-ecb', 'aes-256-cbc', 'des3-128-ecb', 'des3-128-cbc', 'des3-192-ecb', 'des3-192-cbc']
__SUPPORTED_HASH = ['sha2-256', 'sha2-512', 'sha3-256', 'sha3-512']

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Input for decrpytion of cryptographic envelope / signature / seal.')
    parser.add_argument('--mode', metavar='mode', type=str, choices=__SUPPORTED_MODES, default='seal', help='Program mode')
    parser.add_argument('--sim', metavar='sim', type=str, choices=__SUPPORTED_SYMETRIC, default='aes-256-cbc', help='Simetric cryptoalgorithm')
    parser.add_argument('--hash', metavar='hash', choices=__SUPPORTED_HASH, default='sha3-512', type=str, help='Hash function')
    parser.add_argument('--pubkey', metavar='pubkey', type=str, default='keys/reciver-2048-pub.pem', help='Public key of receiver')
    parser.add_argument('--privkey', metavar='privkey', type=str, default='keys/sender-2048-priv.pem', help='Private key of sender')
    parser.add_argument('--message', metavar='message', type=bytes, default=b'Test string', help='Message to encrypt')

    args = vars(parser.parse_args())
    
    mode = args['mode']
    message = args['message']
    print(f'Encrypt. Mode: {mode}. Message: {message.decode()}')
    
    data = encrypt(args)
    if mode == 'seal':
        enc_message, enc_session_key, sig, iv = data
        print(f'Sealed data: {enc_message + enc_session_key + sig}')
    elif mode == 'signature':
        message, signature = data
        print(f'Signature of data: {message + signature}')
    elif mode == 'envelope':
        enc_message, enc_session_key, iv = data
        print(f'Envelope of data: {enc_message + enc_session_key}')