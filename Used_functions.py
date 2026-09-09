import base64, random

def Vigenere_encode(plaintext, key):
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
    output_byte = XOR(plaintext,full_key)
    return output_byte

def XOR(a,b):
    """ 
    Compute XOR of a and b
    Input type: can be either int, hex string or bytes
    Output: XOR result in the same type as the inputs
    """
    if type(a) != type(b):
        raise TypeError("Inputs must be of the same type")
    elif isinstance(a, int):
        return a ^ b
    elif isinstance(a, str):
        if len(a) != len(b):
            raise ValueError("Inputs must be of equal length")
        try: #hex string
            a_int = int(a,16)
            b_int = int(b,16)
            XOR_int = a_int ^ b_int
            XOR_hex = format(XOR_int, f'0{len(a)}x')
            return XOR_hex
        except ValueError: #ascii
            #print("Warning: input for XOR interpreted as ascii, not hex")
            a_byte = a.encode('utf-8')
            b_byte = b.encode('utf-8')
            XOR_bytes = bytes(x ^ y for x,y in zip(a_byte,b_byte))
            return XOR_bytes.decode('utf-8')
    elif isinstance(a, bytes):
        if len(a) != len(b):
            raise ValueError("Inputs must be of equal length")
        else:
            return bytes(x ^ y for x,y in zip(a,b))
    else:
        raise TypeError("Unsupported type")

def score_text_likelihood(input_bytes: bytes) -> int:
    """
    Compute a score for the input bytes, how likely these bytes are text
    """
    byte_values = list(input_bytes)
    printable_special_chars = [33, 38, 39, 46, 63]  # !, &, ', ., ?
    text_like_count = 0
    for byte_value in byte_values:
        # uppercase (65-90), lowercase (97-122)
        if (byte_value > 64 and byte_value < 91) or (byte_value > 96 and byte_value < 123):
            text_like_count += 3
        # space
        elif byte_value == 32:
            text_like_count += 2
        # special characters
        elif byte_value in printable_special_chars:
            text_like_count += 1
        # not used bytes in ascii
        elif byte_value < 9 or 13 < byte_value < 32 or byte_value > 126:
            text_like_count -= 5
    return text_like_count

def XOR_cipher_break(ciphertext):
    """
    Break a XOR cipher with a single character (all bytes XOR'd with same key-byte) by brute-forcing and frequency-analysis.
    (Same as Caesar-cipher)
    Input: ciphertext (bytes)
    Output: plaintext (bytes), key (bytes)
    """
    possible_plains = []
    for i in range(256):
        key_guess = i.to_bytes(1)
        key_bytes = key_guess * int(len(ciphertext))
        plain_bytes = XOR(ciphertext,key_bytes)
        count = score_text_likelihood(plain_bytes)
        possible_plains.append((plain_bytes, count, key_guess))
    possible_plains.sort(key=lambda x: x[1], reverse=True)
    plaintext, final_count, key = possible_plains[0]
    return plaintext, key

def Hamming_Dist(x,y) -> int:
    """
    Compute the Hamming distance between two strings (number of differing bits) or bytes.
    """
    if isinstance(x,str):
        XOR_bytes = XOR(x,y).encode()
    elif isinstance(x,bytes):
        XOR_bytes = XOR(x,y)
    XOR_int = int.from_bytes(XOR_bytes,byteorder='big')
    #TODO: iets met byteorder
    XOR_bits = bin(XOR_int)[2:]
    return XOR_bits.count('1')

def break_vigenere(ciphertext: bytes) -> bytes:
    """
    Break a ciphertext encrypted with Vigenere-cipher (repeating-key XOR).
    
    Parameters:
        ciphertext (bytes): ciphertext to break
    
    Returns:
        plaintexts (list): list of plaintexts in bytes
    """
    candidate_results = []
    #finding keylength
    num_guesses = 10
    key_size_scores = []
    for key_size in range(2,40):
        blocks = [ciphertext[i:i+key_size] for i in range(0,len(ciphertext),key_size)]
        norm_dist = (Hamming_Dist(blocks[0],blocks[1])+Hamming_Dist(blocks[2],blocks[3])+Hamming_Dist(blocks[4],blocks[5]))/ key_size
        #TODO: norm_dist functie hierboven is nog niet optimaal, goede keylength heeft pas 5e beste score
        key_size_scores.append((key_size,norm_dist))
    key_size_scores.sort(key=lambda x: x[1], reverse=False)
    candidate_key_sizes = [x[0] for x in key_size_scores[:num_guesses]]

    #breaking ciphertext
    for keylength in candidate_key_sizes:
        #split ciphertext in blocks of keylength
        cipher_blocks = [ciphertext[i:i+keylength] for i in range(0,len(ciphertext),keylength)]
        block_count = len(cipher_blocks)
        
        #create a cluster for first bytes of each block, a cluster for second bytes of each block, etc.
        clusters = []
        for i in range(keylength):
            cluster_bytes = [block[i] for block in cipher_blocks if len(block) > i]
            clusters.append(bytes(cluster_bytes))

        #solve for each cluster of i-th bytes as single-character XOR
        decoded_clusters = []
        candidate_key = bytearray()
        for cluster in clusters:
            cluster_decoded, key = XOR_cipher_break(cluster)
            decoded_clusters.append(cluster_decoded)
            candidate_key.extend(key)
        
        #redistribute clusters to get plaintext back
        reconstructed_plaintext = bytearray()
        for i in range(block_count):
            for cluster in decoded_clusters:
                if i < len(cluster):
                    reconstructed_plaintext.append(cluster[i])
        plaintext = bytes(reconstructed_plaintext)
        score = score_text_likelihood(plaintext)
        candidate_results.append((plaintext,score,candidate_key,keylength))
    candidate_results.sort(key=lambda x: x[1], reverse=True)
    final_plaintext = candidate_results[0][0]
    final_key = candidate_results[0][2]
    final_keylength = candidate_results[0][3]
    return final_plaintext, final_key

#functions from set 2
def padding(unpadded: bytes, block_length=16) -> bytes:
    num_to_add = block_length - (len(unpadded))%block_length
    padded = unpadded + bytes([num_to_add])*num_to_add
    return padded

def CBC_encrypt(plaintext: bytes, blockcipher, IV=b'\x00' * 16) -> bytes:
    padded_plain = padding(plaintext,16)
    plain_blocks = [padded_plain[i:i+16] for i in range(0,len(padded_plain),16)]
    
    ciphertext = b''
    current_cipher = IV
    for plain_block in plain_blocks:
        current_plain = XOR(current_cipher,plain_block)
        current_cipher = blockcipher.encrypt(current_plain)
        ciphertext += current_cipher
    return ciphertext

def CBC_decrypt(ciphertext: bytes, blockcipher, IV=b'\x00' * 16) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise TypeError("Length input is not multiple of 16 bytes.")
    cipher_blocks = [ciphertext[i:i+16] for i in range(0,len(ciphertext),16)]
    
    plaintext = b''
    previous_cipher = IV
    for cipher_block in cipher_blocks:
        decrypted_block = blockcipher.decrypt(cipher_block)
        plain_block = XOR(decrypted_block,previous_cipher)
        plaintext += plain_block
        previous_cipher = cipher_block
    return plaintext

def random_bytes_gen(len=16):
    """
    Generate random bytes (e.g. to use as key). Default is 16 bytes.
    """
    output = b''
    for i in range(len):
        rand_int = random.randint(0,255)
        output += rand_int.to_bytes()
    return output

#Problem with this unpadding function: what to do if there is no padding? Is that unvalid or not?
def unpadding(padded: bytes, block_length=16) -> bytes:
    """
    unpads bytes that are padded with PKCS #7 padding
    """
    if len(padded) % block_length != 0:
        raise IndexError(f"No valid PKCS #7 padding, length is not a multiple of {block_length}")
    padding_length = padded[-1]
    if padding_length <= block_length and padding_length > 0:
        for i in range(padding_length):
            if padded[-(i+1)] != padding_length:
                raise BufferError("Cannot unpad: No valid PKCS #7 padding")
        return padded[:-padding_length]
    else:
        raise BufferError("Cannot unpad: No valid PKCS #7 padding") #return padded