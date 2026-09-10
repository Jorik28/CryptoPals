from Crypto.Cipher import AES
import base64, random
from Used_functions import padding, unpadding, random_bytes_gen, CBC_encrypt, CBC_decrypt, XOR

def encrypt_oracle(key: bytes) -> bytes:
    string_list = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
                   'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
                   'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
                   'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
                   'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
                   'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
                   'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
                   'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
                   'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
                   'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']
    rd_i = random.randint(0,9)
    random_string = string_list[rd_i]
    string_bytes = base64.b64decode(random_string)
    #string_bytes = b'123456789012345 123456789012345 Hello'
    plaintext = string_bytes
    cipher = AES.new(key, AES.MODE_ECB)
    IV = random_bytes_gen(16)
    return CBC_encrypt(plaintext,cipher,IV), IV

def check_valid_padding(ciphertext: bytes, key: bytes, IV: bytes) -> bool:
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = CBC_decrypt(ciphertext, cipher, IV)
    try:
        plaintext = unpadding(decrypted_text)
        return True
    except:
        return False

key = random_bytes_gen(16)
ciphertext, IV = encrypt_oracle(key)
IV_and_cipher = IV + ciphertext

#Breaking algorithm
list_cookies = []
while len(list_cookies) < 10:
    ciphertext, IV = encrypt_oracle(key)
    IV_and_cipher = IV + ciphertext
    num_blocks = int(len(IV_and_cipher)/16)
    plaintext_bytes = b''
    for block in range(num_blocks-1):
        xor_str = b'\x00' * (len(IV_and_cipher))
        for i in range(16,32):
            guess_byte = 255
            padding_byte = bytes([i-15])
            xor_str = xor_str[:-(i+1)] + bytes([guess_byte]) + xor_str[-i:]
            cipher_guess = XOR(IV_and_cipher, xor_str)
            while not check_valid_padding(cipher_guess[16:], key, cipher_guess[:16]):
                if guess_byte == 0:
                    print("Plaintext found so far:", plaintext_bytes)
                    print("Failed at byte number:", i)
                    print("Current padding_byte:", padding_byte)
                    print("Current xor_str:", xor_str)
                    raise IndexError("No byte found that gives a valid padding")
                guess_byte -= 1
                xor_str = xor_str[:-(i+1)] + bytes([guess_byte]) + xor_str[-i:]
                cipher_guess = XOR(IV_and_cipher, xor_str)
            
            if check_valid_padding(cipher_guess[16:], key, cipher_guess[:16]):
                xored_byte = bytes([guess_byte])
                last_plain_byte = XOR(xored_byte, padding_byte)
                plaintext_bytes = last_plain_byte + plaintext_bytes
                #prepare for next byte guessing
                for j in range(16,i+1):
                    next_padding_byte = bytes([i-14])
                    difference = XOR(padding_byte,next_padding_byte)
                    new_byte = XOR(difference,xor_str[-(j+1):-j])
                    xor_str = xor_str[:-(j+1)] + new_byte + xor_str[-j:]
            else:
                raise SyntaxError("This shouldn't happen.")
        IV_and_cipher = IV_and_cipher[:-16]
    #print("This is the plaintext:", plaintext_bytes)
    if unpadding(plaintext_bytes) not in list_cookies:
        list_cookies.append(unpadding(plaintext_bytes))

list_cookies.sort()
for str in list_cookies:
    print(str)

