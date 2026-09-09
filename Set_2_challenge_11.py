from Crypto.Cipher import AES
import random
from Used_functions import CBC_encrypt, padding, Hamming_Dist

#for challenge 11
def random_bytes_gen(len=16):
    """
    Generate random bytes (e.g. to use as key). Default is 16 bytes.
    """
    output = b''
    for i in range(len):
        rand_int = random.randint(0,255)
        output += rand_int.to_bytes()
    return output

def encryption_oracle_ECB_CBC(input: bytes) -> bytes:
    """
    Simulates an encryption oracle. 
    Probability 1/2 that input is encrypted with AES-128-ECB
    Probability 1/2 that input is encrypted with AES-128-CBC
    (Appends 5-10 bytes (count chosen randomly) before and after the plaintext)
    """
    append_before = random.randint(5,10)
    append_after = random.randint(5,10)
    plaintext = random_bytes_gen(append_before) + input + random_bytes_gen(append_after)
    padded_plain = padding(plaintext,16)
    
    key = random_bytes_gen()
    cipher = AES.new(key, AES.MODE_ECB)
    
    choose_mode = random.randint(0,1)
    if choose_mode:
        #encrypt with ECB
        ciphertext = cipher.encrypt(padded_plain)
    if not choose_mode:
        #encrypt with CBC
        ciphertext = CBC_encrypt(padded_plain, cipher)
    return ciphertext, choose_mode

def detect_ECB_CBC(input: bytes) -> str:
    """
    Guesses whether the input in encrypted with ECB or CBC mode.
    Output is a string: either 'ECB' or 'CBC'
    """
    if len(input) % 16 != 0:
        raise IndexError("Input length is", num_lines, "not divisible by 16.")
    num_lines = int(len(input)/16)
    for i in range(num_lines-1):
        for j in range(i+1,num_lines):
            if Hamming_Dist(input[16*i:16*(i+1)],input[16*j:16*(j+1)]) == 0:
                return 1 #ECB
    return 0 #CBC

plaintext = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
total_guesses = 1000
correct_guesses = 0
for i in range(total_guesses):
    challenge, which_mode = encryption_oracle_ECB_CBC(plaintext)
    answer = detect_ECB_CBC(challenge)
    if answer == which_mode:
        correct_guesses += 1
print(correct_guesses, "out of", total_guesses, "correct")
print("Score:", str(round((correct_guesses/total_guesses)*100,1)) + "%")