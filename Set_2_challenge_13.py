from Crypto.Cipher import AES
from Used_functions import random_bytes_gen, padding

def kv_parsing(cookie: str) -> dict:
    """
    Input: a cookie, for example 'foo=bar&baz=qux&zap=zazzle'
    Output: a dictionary, for example {foo: 'bar', baz: 'qux', zap: 'zazzle'}
    """
    json = dict()
    cookie_split = cookie.split('&')
    for keyvalue in cookie_split:
        key, value = keyvalue.split('=')
        json[key] = value
    return json

def profile_for(email):
    """
    Creates a cookie for the given email with uid = 10 and role = user
    """
    uid = 10
    role = 'user'
    if '&' in email or '=' in email:
        email = email.replace('&', '_and_')
        email = email.replace('=', '_is_')
    cookie = 'email=' + str(email) + '&uid=' + str(uid) + '&role=' + str(role)
    return cookie

def unpadding(padded: bytes, block_length=16) -> bytes:
    padding_length = padded[-1]
    if padding_length < block_length:
        return padded[:-padding_length]
    else:
        return padded

def encrypt(key: bytes, plain: str) -> bytes:
    """
    Encrypts a plaintext with AES in ECB mode
    """
    cipher = AES.new(key, AES.MODE_ECB)
    plain_bytes = plain.encode('utf-8')
    padded_plain = padding(plain_bytes,16)
    return cipher.encrypt(padded_plain)

def decrypt_and_parse(key: bytes, ciphertext: bytes) -> dict:
    """
    Decrypts a cookie encrypted with AES in ECB mode and outputs a dictionary
    """
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext_bytes = cipher.decrypt(ciphertext)
    print("plaintext_bytes:", plaintext_bytes)
    unpadded_plain = unpadding(plaintext_bytes)
    plaintext = unpadded_plain.decode('utf-8')
    return kv_parsing(plaintext)

#tests
cookie = 'foo=bar&baz=qux&zap=zazzle'
foobar_test = kv_parsing(cookie)
#print(foobar_test)

email = 'foo@bar.com'
cookie_test = profile_for(email)
storage_test = kv_parsing(cookie_test)
#print(storage_test)

key = random_bytes_gen()

#user input here
user_input1 = 'hier10bytsadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
create_cookie1 = profile_for(user_input1)
ciphertext1 = encrypt(key, create_cookie1)
print("User input:", user_input1)
print("Ciphertext:", ciphertext1)
cipher_split = []
for i in range(0,len(ciphertext1),16):
    cipher_split.append(ciphertext1[i:i+16])
print("Second ciphertext block:", cipher_split[1])

user_input2 = 'foooo@bar.com'
create_cookie2 = profile_for(user_input2)
ciphertext2 = encrypt(key, create_cookie2)
print("User input:", user_input2)
print("Ciphertext:", ciphertext2)
#replace last ciphertext block with the block encrypting 'admin' + padding to replace 'user' to 'admin'
final_ciphertext = ciphertext2[:-16] + cipher_split[1]

#check if broken
out = decrypt_and_parse(key, final_ciphertext)
print("Output:", out)
if out['role'] == 'admin':
    print('\nCongratulations! You made an admin profile and broke this encryption.\n')

"""
Notes for myself (to break this scheme):
if input is length 9, then cipher is 32 bytes
if input is length 10, then cipher is 48 bytes
==> empty unpadded plaintext has length 23 bytes 
I realize that I already know this since I know its of the following form: email=...&uid=10&role=user
'email=' has length 6 and '&uid=10&role=user' has length 17

Approach idea:
query such that we have a block of 16 bytes with email=... and then encrypt role=admin plus padding to see what the cipher is, then append that cipher
No, didn't work because the '=' sign is replaced

Second approach idea (this did work!):
Query such that we have a block of 16 bytes with email=... and then encrypt admin plus padding to obtain its cipher, 
then make sure that in the ciphertext the last block only encrypts 'user' and replace this cipher block with the cipher of 'admin'.
"""