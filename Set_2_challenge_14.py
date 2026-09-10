from Crypto.Cipher import AES
import base64, random
from Used_functions import padding, random_bytes_gen

#copied from Set 2, challenge 12 and added random bytes as prefix
def encryption_oracle_ECB(input: bytes, key: bytes, randomness: bytes) -> bytes:
    """
    Simulates an encryption oracle that appends a secret string to the input and a random number of random bytes as prefix and then encrypts AES-128-ECB
    AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
    """
    secret_string = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    secret_bytes = base64.b64decode(secret_string)
    plaintext = randomness + input + secret_bytes
    padded_plain = padding(plaintext,16)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(padded_plain)
    return ciphertext

rd = random.randint(0,100)
random_bytes = random_bytes_gen(rd)

random_key = random_bytes_gen()

"""
Below is copied from challenge 12
"""
block_size = 16

#discover length of random bytes
first_plain = b''
first_cipher = encryption_oracle_ECB(first_plain, random_key, random_bytes)
second_plain = b'a'
second_cipher = encryption_oracle_ECB(second_plain, random_key, random_bytes)
num_of_blocks = int(len(first_cipher) / block_size)
for i in range(len(first_cipher)):
    if first_cipher[i] != second_cipher[i]:
        if i % 16 != 0:
            print("Random bytes had length", rd)
            print("This were the random bytes:", random_bytes)
            raise ValueError("First different byte is no multiple of 16")
        first_different_byte = i
        num_random_blocks = int(first_different_byte/block_size) +1
        print("First different byte is:", first_different_byte+1)
        print("Length of random bytes is between:", (num_random_blocks-1) * block_size, "and", num_random_blocks * block_size-1)
        break

dummy_plain = b''
previous_cipher = encryption_oracle_ECB(dummy_plain, random_key, random_bytes)
for j in range(block_size+1):
    dummy_plain += b'a'
    current_cipher = encryption_oracle_ECB(dummy_plain, random_key, random_bytes)
    if previous_cipher[first_different_byte] == current_cipher[first_different_byte]:
        len_random_mod = 16 - (len(dummy_plain)-1)
        len_random_bytes = first_different_byte + len_random_mod
        print("Random bytes have length of:", len_random_bytes)
        break
    else:
        previous_cipher = current_cipher

if len_random_bytes != rd:
    print("\nPSST, you did NOT guessed the number of random bytes! SOMETHINGS WRONG HERE\n")
    print("These are the random bytes:", random_bytes)
    print("These are", rd, "bytes")

#discover length unknown string
dummy_plain = b''
previous_cipher = encryption_oracle_ECB(dummy_plain, random_key, random_bytes)
for i in range(100):
    dummy_plain += b'a'
    current_cipher = encryption_oracle_ECB(dummy_plain, random_key, random_bytes)
    if len(current_cipher) != len(previous_cipher):
        len_mod_block_length = len(dummy_plain)-1
        ciphertext_length = len(previous_cipher)
        len_unknown_str = ciphertext_length - len_mod_block_length
        len_secret_bytes = len_unknown_str - len_random_bytes
        print("Length of the total unknown string is:", len_unknown_str)
        print("Length of secret string is:", len_secret_bytes)
        break
    else:
        previous_cipher = current_cipher

#brute-force
unknown_string = b''
for index in range(len_secret_bytes):
    found = False
    pos_in_block = index % block_size
    which_block = int(index/block_size)
    len_a_str = block_size-1-pos_in_block
    plain_block_a = (b'b' * (block_size-len_random_mod)) + (b'a' * len_a_str)
    goal_ciphertext = encryption_oracle_ECB(plain_block_a, random_key, random_bytes)[:block_size * (num_random_blocks + which_block + 1)]
    for i in range(128):
        byte_guess = i.to_bytes()
        plain_guess = plain_block_a + unknown_string + byte_guess
        guess_ciphertext = encryption_oracle_ECB(plain_guess, random_key, random_bytes)[:block_size * (num_random_blocks + which_block + 1)]
        if guess_ciphertext == goal_ciphertext:
            found = True
            unknown_string += byte_guess
            break
    if not found:
        raise IndexError("All bytes tried, but none of them worked.")

secret_string = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
secret_bytes = base64.b64decode(secret_string)
if unknown_string == secret_bytes:
    print("\nCongratulations! You solved challenge 14!\n")
    print(unknown_string.decode())