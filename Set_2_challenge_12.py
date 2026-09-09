from Crypto.Cipher import AES
import random, base64
from Used_functions import CBC_encrypt, padding, Hamming_Dist, random_bytes_gen

def encryption_oracle_ECB(input: bytes, key: bytes) -> bytes:
    """
    Simulates an encryption oracle that appends a secret string to the input and then encrypts AES-128-ECB
    AES-128-ECB(your-string || unknown-string, random-key)
    """
    secret_string = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    secret_bytes = base64.b64decode(secret_string)
    plaintext = input + secret_bytes
    padded_plain = padding(plaintext,16)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(padded_plain)
    return ciphertext

def detect_ECB_CBC(input: bytes) -> str:
    """
    Guesses whether the input in encrypted with ECB or CBC mode.
    Based on if there are two identical cipher blocks
    Output is a string: either 'ECB' or 'CBC'
    """
    if len(input) % 16 != 0:
        raise IndexError("Input length is not divisible by 16.")
    num_lines = int(len(input)/16)
    for i in range(num_lines-1):
        for j in range(i+1,num_lines):
            if Hamming_Dist(input[16*i:16*(i+1)],input[16*j:16*(j+1)]) == 0:
                return 1 #ECB
    return 0 #CBC

random_key = random_bytes_gen()

#discover block size
dummy_plain = b'a'
previous_cipher = encryption_oracle_ECB(dummy_plain, random_key)
for i in range(100):
    dummy_plain += b'a'
    current_cipher = encryption_oracle_ECB(dummy_plain, random_key)
    if current_cipher[0] == previous_cipher[0]:
        block_size = len(dummy_plain)-1
        if current_cipher[:block_size] == previous_cipher[:block_size]:
            #print("Block size is:", block_size)
            break
    else:
        previous_cipher = current_cipher

#discover length unknown string
dummy_plain = b''
previous_cipher = encryption_oracle_ECB(dummy_plain, random_key)
for i in range(100):
    dummy_plain += b'a'
    current_cipher = encryption_oracle_ECB(dummy_plain, random_key)
    if len(current_cipher) != len(previous_cipher):
        len_mod_block_length = len(dummy_plain)-1
        ciphertext_length = len(previous_cipher)
        len_unknown_str = ciphertext_length - len_mod_block_length
        break
    else:
        previous_cipher = current_cipher

#detect ECB mode
challenge = encryption_oracle_ECB(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', random_key)
answer = detect_ECB_CBC(challenge)
if answer:
    None #print("ECB mode is detected")

#brute-force
unknown_string = b''
for index in range(len_unknown_str):
    found = False
    pos_in_block = index % block_size
    which_block = int(index/block_size)
    len_a_str = block_size-1-pos_in_block
    plain_block_a = (b'a' * len_a_str)
    goal_ciphertext = encryption_oracle_ECB(plain_block_a, random_key)[:block_size * (which_block + 1)]
    for i in range(128):
        byte_guess = i.to_bytes()
        plain_guess = plain_block_a + unknown_string + byte_guess
        guess_ciphertext = encryption_oracle_ECB(plain_guess, random_key)[:block_size * (which_block + 1)]
        if guess_ciphertext == goal_ciphertext:
            #print('Length_ciphertext', len(guess_ciphertext))
            found = True
            unknown_string += byte_guess
            break
    if not found:
        raise IndexError("All bytes tried, but none of them worked.")

secret_string = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
secret_bytes = base64.b64decode(secret_string)
if unknown_string == secret_bytes:
    print("Congratulations! You solved challenge 12!")
    print(unknown_string.decode())
