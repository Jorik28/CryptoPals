from Crypto.Cipher import AES
import base64
from Used_functions import XOR

#challenge 9
unpadded = b'YELLOW SUBMARINE'
solution = b'YELLOW SUBMARINE\x04\x04\x04\x04'

def padding(unpadded: bytes, block_length: int) -> bytes:
    num_to_add = (-len(unpadded))%block_length
    padded = unpadded + bytes([num_to_add])*num_to_add
    return padded

padded = padding(unpadded, 20)

if padded == solution:
    print("Well done! You solved challenge 9")

#challenge 10
def CBC_encrypt(plaintext: bytes, blockcipher) -> bytes:
    padded_plain = padding(plaintext,16)
    plain_blocks = [padded_plain[i:i+16] for i in range(0,len(padded_plain),16)]
    
    IV = b'\x00' * 16
    ciphertext = b''
    current_cipher = IV
    for plain_block in plain_blocks:
        current_plain = XOR(current_cipher,plain_block)
        current_cipher = blockcipher.encrypt(current_plain)
        ciphertext += current_cipher
    return ciphertext

def CBC_decrypt(ciphertext: bytes, blockcipher) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise TypeError("Length input is not multiple of 16 bytes.")
    cipher_blocks = [ciphertext[i:i+16] for i in range(0,len(ciphertext),16)]
    
    IV = b'\x00' * 16
    plaintext = b''
    previous_cipher = IV
    for cipher_block in cipher_blocks:
        decrypted_block = blockcipher.decrypt(cipher_block)
        plain_block = XOR(decrypted_block,previous_cipher)
        plaintext += plain_block
        previous_cipher = cipher_block
    return plaintext

with open('set2_challenge10.txt', 'r', encoding='utf-8') as f:
    input_base64 = f.read().strip() #base64

ciphertext = base64.b64decode(input_base64) #bytes
key = b'YELLOW SUBMARINE'
cipher = AES.new(key, AES.MODE_ECB)
output = CBC_decrypt(ciphertext, cipher)
#print(output.decode('ascii',errors='replace'))
print("Well done! You solved challenge 10")