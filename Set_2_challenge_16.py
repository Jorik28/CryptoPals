from Crypto.Cipher import AES
import base64, random
from Used_functions import padding, unpadding, random_bytes_gen, CBC_encrypt, CBC_decrypt, XOR

def encrypt(plaintext: str, key: bytes) -> bytes:
    prepend = "comment1=cooking%20MCs;userdata="
    append = ";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = plaintext.replace('=', "_IS_")
    plaintext = plaintext.replace(';', "_SEMI_")
    string = prepend + plaintext + append
    plain_bytes = string.encode('utf-8')
    
    padded = padding(plain_bytes, 16)
    
    cipher = AES.new(key, AES.MODE_ECB)
    return CBC_encrypt(padded, cipher)

def decrypt(ciphertext: bytes, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_bytes = CBC_decrypt(ciphertext, cipher)
    unpadded = unpadding(decrypted_bytes, 16)
    decrypted_str = unpadded.decode('utf-8', errors='replace')
    
    data_dict = dict()
    str_split = decrypted_str.split(';')
    for tuple in str_split:
        try:
            key, value = tuple.split('=')
        except:
            return "Not a valid cookie: " + decrypted_str
        key = key.replace("_IS_", '=')
        key = key.replace("_SEMI_", ';')
        value = value.replace("_IS_", '=')
        value = value.replace("_SEMI_", ';')
        data_dict[key] = value
    if 'admin' in data_dict:
        print("This is the dictionary:", data_dict)
        return True
    else:
        return data_dict


#User input and ciphertext modification
inp = "blockof 16 bytes{admin}true"
random_key = random_bytes_gen(16)
ciphertext = encrypt(inp, random_key)
xor_str = b'@\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00'
third_block = XOR(ciphertext[32:48], xor_str)
new_ciphertext = ciphertext[:32] + third_block + ciphertext[48:]
out2 = decrypt(new_ciphertext, random_key)
print("Input:", inp)
print("Ciphertext block 3 was:", ciphertext[32:48])
print("Ciphertext block 3 is :", new_ciphertext[32:48])
print("Output:", out2)
if out2 == True:
    print("!!!!!!!!!!!!!\n!!!!!!!!!!!!!\nYIPPIE YOU SOLVED THE CHALLENGE! YOU CREATED AN ADMIN PROFILE!\n!!!!!!!!!!!!!\n!!!!!!!!!!!!!")

"""
comment1=cooking    %20MCs;userdata=            �Y  ��!�^ҹ���"�ډ�~q�����        (ent2=%20like%20    a%20pound%20of%20bacon
comment1=cooking    %20MCs;userdata=    blockof 16 bytes    {admin}true{;com    ment2=%20like%20    a%20pound%20of%20bacon

h -> !
104 -> 33
1101000 -> 0100001: difference is 1001001 = 73 = I

M -> l
77 -> 108
1001101 -> 1101100

Notes:
Okay, a bitflip in ciphertext scrambles the block and flips the same bits in the next block
Note that XOR( { , @ ) = ; and XOR( } , @ ) = =, so in plain we can write { and } and then flip with @ to obtain ; and =

So user input must be a block of 16 bytes and then {admin}true{
"""