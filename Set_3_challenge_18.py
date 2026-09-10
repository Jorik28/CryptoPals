from Crypto.Cipher import AES
import base64, random
from Used_functions import padding, unpadding, random_bytes_gen, CBC_encrypt, CBC_decrypt, XOR

challenge_string = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
ciphertext = base64.b64decode(challenge_string)

def gen_keystream(key: bytes, length: int, nonce=0) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    nonce_bytes = nonce.to_bytes(8, byteorder='little')
    block_count = 0
    keystream = b''
    while len(keystream) < length:
        counter_bytes = block_count.to_bytes(8, byteorder='little')
        keystream += cipher.encrypt(nonce_bytes + counter_bytes)
        block_count += 1
    return keystream[:length]

key = b'YELLOW SUBMARINE'
keystream = gen_keystream(key, len(ciphertext))
plaintext = XOR(keystream, ciphertext)
print(plaintext)