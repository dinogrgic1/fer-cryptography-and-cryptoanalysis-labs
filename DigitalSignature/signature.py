import argparse
from core import mode_select

__SUPPORTED_SIMETRIC = ['aes-ecb', 'aes-cbc', 'des3-ecb', 'des3-cbc']
__SUPPORTED_ASYIMETRIC = ['rsa-1024', 'rsa-2048', 'rsa-3072', 'rsa-4096']
__SUPPORTED_HASH = ['sha2-256', 'sha2-512', 'sha3-256', 'sha3-512']
__SUPPORTED_MODES = ['envelope', 'signature', 'seal']

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--mode', metavar='mode', type=str, choices=__SUPPORTED_MODES, default='seal', help='Program mode')
    parser.add_argument('--sim', metavar='sim', type=str, choices=__SUPPORTED_SIMETRIC, default='aes-cbc', help='Simetric cryptoalgorithm')
    parser.add_argument('--asim', metavar='asim', choices=__SUPPORTED_ASYIMETRIC, default='rsa-2048', type=str, help='Asimetric cryptoalgorithm')
    parser.add_argument('--hash', metavar='hash', choices=__SUPPORTED_HASH, default='sha3-256', type=str, help='Hash function')
    parser.add_argument('--pubkey', metavar='pubkey', type=str, default='reciver-1024-pub.pem', help='Public key of receiver')
    parser.add_argument('--privkey', metavar='privkey', type=str, default='sender-1024-priv.pem', help='Private key of sender')

    mode_select(parser.parse_args())