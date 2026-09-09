"""
See https://cryptopals.com/ for the challenges.
"""
import base64

#challenge 1
def hex_to_base64(hex):
    """
    Convert a string of hexadecimal characters to a base64 string.
    """
    raw_bytes = bytes.fromhex(hex)
    base64_output = base64.b64encode(raw_bytes)
    output = base64_output.decode()
    return output

input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
ans = hex_to_base64(input)
if ans == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t":
    print("Good job! You solved challenge 1")

#challenge 2
def XOR_for_hexstring(a_str,b_str):
    """
    Compute the XOR for two hexadecimal strings, output is a hexadecimal string
    """
    if len(a_str) != len(b_str):
        raise ValueError("Input is not of equal length for XOR")
    a_int = int(a_str,16)
    b_int = int(b_str,16)
    XOR_int = a_int ^ b_int
    #format transforms XOR_int to hex of length len(a_str) padded with zeroes on the left
    XOR_hex2 = format(XOR_int, f'0{len(a_str)}x')
    return XOR_hex2

input_1 = '1c0111001f010100061a024b53535009181c'
input_2 = '686974207468652062756c6c277320657965'
ans_2 = XOR_for_hexstring(input_1, input_2)
if ans_2 == '746865206b696420646f6e277420706c6179':
    print("Good job! You solved challenge 2")

#challenge 3
def XOR_cipher_break(ciphertext):
    """
    Break a XOR cipher with a single character by brute-forcing and frequency-analysis.
    Input: hexadecimal string
    Output: string
    """
    possible_plains = []
    for i in range(256):
        key_guess = format(i, '02x')
        key_str = key_guess * int(len(ciphertext)/2)
        plain_hex = XOR_for_hexstring(ciphertext,key_str)
        plain_bytes = bytes.fromhex(plain_hex)
        plain_str = plain_bytes.decode('ascii', errors='replace')
        plain_list = list(plain_bytes)
        count = 0
        for num in plain_list:
            if (num > 64 and num < 91) or (num > 96 and num < 123) or num == 32 or num == 39:
                count += 1
        possible_plains.append((plain_str, count))
    possible_plains.sort(key=lambda x: x[1], reverse=True)
    final_plain, final_count = possible_plains[0]
    return final_plain, final_count

hex_encoded_string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
ans_3 = XOR_cipher_break(hex_encoded_string)[0]
#print(ans_3)
print('Good job! You solved challenge 3')

#challenge 4
with open('set1_challenge4.txt', 'r', encoding='utf-8') as file:
    list_strings = [line.strip() for line in file]

counter = 0
output = ''
for string in list_strings:
    plain, count = XOR_cipher_break(string)
    if count > counter:
        output = plain
        counter = count
#print(output)
print("Good job! You solved challenge 4")

#challenge 5
def XOR_for_bytes(a,b):
    """
    Compute the XOR for two bytes, output is a byte
    """
    if len(a) != len(b):
        raise ValueError("objects must have equal length to XOR")
    return bytes(x ^ y for x,y in zip(a,b))

def repeating_XOR_encode(plaintext, key):
    """
    Encode a plaintext with repeating-key XOR (Vigenere-cipher), 
    If the key is 'ICE', then the first byte is encoded with I, second with C, third with E, fourth with I, etc.
    Input types: either string or bytes
    Output type: bytes
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    elif not isinstance(plaintext, bytes):
        raise TypeError("This is not a valid type")
    if isinstance(key, str):
        key = key.encode()
    elif not isinstance(key, bytes):
        raise TypeError("This is not a valid type")
    
    full_key = key * (int(len(plaintext)/len(key))+1)
    full_key = full_key[:len(plaintext)]
    output_byte = XOR_for_bytes(plaintext,full_key)
    return output_byte

plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = 'ICE'
ans_5 = repeating_XOR_encode(plaintext,key).hex()
check_5 = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
if ans_5 == check_5:
    print("Good job! You solved challenge 5")

test_plain = 'gewoon maar een normale tekst om te proberen.'
test_key = 'geheime sleutel'
cipher = repeating_XOR_encode(test_plain, test_key)
#print('ciphertext:', cipher.hex())
decript_cipher = repeating_XOR_encode(cipher, test_key)
#print(decript_cipher.decode('ascii'))
