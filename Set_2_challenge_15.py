from Used_functions import padding, random_bytes_gen

random_bytes = random_bytes_gen(10)
padded_bytes = padding(random_bytes) 

def unpadding(padded: bytes, block_length=16) -> bytes:
    """
    unpads bytes that are padded with PKCS #7 padding
    """
    padding_length = padded[-1]
    if padding_length < block_length:
        for i in range(padding_length):
            if padded[-(i+1)] != padding_length:
                raise BufferError("Cannot unpad: No valid PKCS #7 padding")
        return padded[:-padding_length]
    else:
        return padded

test_bytes = b'ICE ICE BABY\x05\x05\x05\x05\x05'
unpad = unpadding(padding(test_bytes))
print("With padding:", test_bytes)
print("Padding removed:", unpad)