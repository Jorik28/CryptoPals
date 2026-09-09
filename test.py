# Python program to illustrate the
# conversion of Binary to ASCII

# Initializing a binary string in the form of
# 0 and 1, with base of 2
binary_int = int('01100110011011000110000101100111011110110111011101100101011011000101111101110110011001010110010101101100010111110110001101101001011010100110011001100101011100100111010001101010011001010111001101011111011110100110111101111101', 2);

# Getting the byte number
byte_number = binary_int.bit_length() + 7 // 8

# Getting an array of bytes
binary_array = binary_int.to_bytes(byte_number, "big")

# Converting the array into ASCII text
ascii_text = binary_array.decode()

# Getting the ASCII value
print(ascii_text)