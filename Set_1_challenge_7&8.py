from Crypto.Cipher import AES
import base64
from Used_functions import score_text_likelihood, Hamming_Dist

#challenge 7
key = b'YELLOW SUBMARINE'
cipher = AES.new(key, AES.MODE_ECB)

with open('set1_challenge7.txt', 'r', encoding='utf-8') as file:
    input_str = file.read().strip() #base64

ciphertext = base64.b64decode(input_str) #bytes
plaintext = cipher.decrypt(ciphertext)
#print(plaintext.decode('ascii',errors='replace'))

#challenge 8
with open('set1_challenge8.txt', 'r', encoding='utf-8') as f:
    input_hex = [line.strip() for line in f.readlines()] #hex

input_bytes = [bytes.fromhex(line) for line in input_hex] #bytes

def detect_AES_ECB(input: bytes) -> bytes:
    candidate_line_num = []
    for line_num in range(len(input)):
        for i in range(9):
            for j in range(i+1,10):
                if Hamming_Dist(input[line_num][16*i:16*(i+1)],input[line_num][16*j:16*(j+1)]) == 0:
                    if line_num not in candidate_line_num:
                        candidate_line_num.append(line_num)

    if len(candidate_line_num) == 1:
        final_line_num = candidate_line_num[0]
        encryped_line = input[final_line_num]
    else:
        raise ValueError("There are multiple lines encrypted with AES-128-ECB")
    return encryped_line, final_line_num

encrypted_line, line_num = detect_AES_ECB(input_bytes)
print("This is the line encryptes with AES-128-ECB (per 16 bytes):")
for i in range(0,len(encrypted_line),16):
    print(encrypted_line[i:i+16])

"""
key_guesses = []
for byte_num in range(65,91):
    letter = byte_num.to_bytes()
    key_guesses.append(letter*16)

key_likelihood = []
for key in key_guesses:
    cipher = AES.new(key, AES.MODE_ECB)
    key_score = 0
    for i in range(0,len(encrypted_line),16):
        plaintext = cipher.decrypt(encrypted_line[i:i+16])
        key_score += score_text_likelihood(plaintext)
    key_likelihood.append((key,key_score,plaintext))
key_likelihood.sort(key=lambda x: x[1], reverse=True)
for plain in [x[2] for x in key_likelihood[:10]]:
    print(plain)
"""