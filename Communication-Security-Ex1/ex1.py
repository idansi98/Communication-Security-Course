#from Cryptodome.Cipher import AES  #Works
#from Cryptodome.Util.Padding import pad,unpad


try:
    from Cryptodome.Cipher import DES
    from Cryptodome.Util.Padding import pad,unpad
    import sys
except ImportError:
    import subprocess
    import sys

    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pycryptodome'])
    from Cryptodome.Cipher import DES
    from Cryptodome.Util.Padding import pad,unpad



#Padd the 'Hello World' string to be 16 long
padded_data = pad(b'Hello World', DES.block_size)
#print(padded_data)

def print_c_in_hexa(c):
    for i in c:
        print(hex(i), end=' ')

#Create a new DES instance to encrypt data in CBC mode with the key = 'poaisfun' and IV = '\x00'*8', print the ciphertext in hexa.
#The reuslt should be 0x33 0xaa 0xa3 0x1 0x7e 0x45 0x33 0x7b 0xd3 0x63 0x42 0xb3 0x92 0xb 0xe6 0x56.
des = DES.new(b'poaisfun', DES.MODE_CBC, b'\x00'*8)
ciphertext = des.encrypt(padded_data)
# print('A')
# print_c_in_hexa(ciphertext)
# print('A')

#Decrypt the ciphertext from the previous question and print the plaintext, the reuslt should be b'Hello World'.
des = DES.new(b'poaisfun', DES.MODE_CBC, b'\x00'*8)
plaintext = des.decrypt(ciphertext)
plaintext = unpad(plaintext, DES.block_size)
# print('B')
# print(plaintext)
# print('B')
   
#Write a xor fucntion that takes 3 bits and returns the result of the xor operation on them
def xor(a, b, c):
    return bytes([a ^ b ^ c])

# print(xor(0,0,0))
# print(xor(0,0,1))
# print(xor(0,1,0))
# print(xor(0,1,1))
# print(xor(1,0,0))
# print(xor(1,0,1))
# print(xor(1,1,0))
# print(xor(1,1,1))


#This Oracle function checks whether the ciphertext is a valid DES ciphertext or not.
def Oracle(ciphertext, key, iv):
    try:
        des = DES.new(key, DES.MODE_CBC, iv)
        plaintext_tag = des.decrypt(ciphertext)
        #print(plaintext_tag)
        plaintext_tag = unpad(plaintext_tag, DES.block_size)
        return True
    except:
        return False


# def test_oracle(ciphertext):
#     original_bytes = ciphertext
#     index_to_change = 5 #index
#     new_byte = b'\x50'  # New byte value
#     modified_bytes = original_bytes[:index_to_change] + new_byte + original_bytes[index_to_change + 1:]
#     print_c_in_hexa(modified_bytes)
#     print(Oracle(modified_bytes, b'poaisfun', b'\x00'*8))

# test_oracle(ciphertext)
# print(Oracle(ciphertext, b'poaisfun', b'\x00'*8))

# #c is a concatenation of a block of 0 and the second block of the ciphertext
# def create_c_second_block():
#     c = b'\x00'*8 + ciphertext[8:16]
#     print_c_in_hexa(c)
#     return c

# c = create_c_second_block()
# #Increase c's eight byte by one till we get True.
# def run_till_true(c):
#     while not Oracle(c, b'poaisfun', b'\x00'*8):
#         c = c[:7] + bytes([c[7] + 1]) + c[8:]
#     return c        

# c = run_till_true(c)
# print_c_in_hexa(c)

# #Using the equation from class and the xor function, let's find the second block's last byte.
# #The answer Needs to be 0x05. 
# p = xor(0x01, ciphertext[7], c[7])
# #print(hex(p[0]))

# #Using the equation from class and the xor function, let's find what c'[7] should be so P'_2[7] = 0x02, we already know P_2[7].
# Xj = xor(0x02, ciphertext[7], p[0])
# c_tag = c[0:7] + bytes([Xj[0]]) + ciphertext[8:]
# #print_c_in_hexa((c_tag))

#Instead of doing one step, make the previous code into a loop that will find the second block of the plaintext.
#The answer should be b'rld\x00\x00\x00\x00\x00'.


# def run_till_true_general(c, i):
#     while not Oracle(c, b'poaisfun', b'\x00'*8):
#         c = c[:i] + bytes([c[i] + 1]) + c[i + 1:]  
#     return c

# def find_second_block():
#     Xj = bytes([0x00] * 8)
#     plaintext_second_block = bytes([0x00] * 8)
#     c = create_c_second_block()
#     for i in range(7, -1, -1):
#         Xj = bytes([0x00] * 8)
#         for j in range(7, i, -1):
#             p = plaintext_second_block[j]
#             xj = xor(0x01 + 7 - i, ciphertext[j], p)[0]
#             Xj = Xj[:j] + bytes([xj]) + Xj[j + 1:]
#         c = Xj + ciphertext[8:16]
#         c = run_till_true_general(c, i)
#         p = xor(0x01 + 7 - i, ciphertext[i], c[i])[0]
#         plaintext_second_block = plaintext_second_block[:i] + bytes([p]) + plaintext_second_block[i + 1:]

#     print_c_in_hexa(plaintext_second_block)    
# find_second_block()

def run_till_found(c, i, key, iv):
    while not Oracle(c, key, iv):
        c = c[:i] + bytes([c[i] + 1]) + c[i + 1:]  
    return c 

def create_c_block(i):
    c = b'\x00'*8 + ciphertext[i:i + 8]
    return c

def find_block(k, ciphertext, key, iv):
    Xj = bytes([0x00] * 8)
    plaintext_block = bytes([0x00] * 8)
    start_index = (k - 1) * 8
    c = create_c_block(start_index)
    for i in range(7, -1, -1):
        Xj = bytes([0x00] * 8)
        for j in range(7, i, -1):
            p = plaintext_block[j]
            if start_index != 0:
                xj = xor(0x01 + 7 - i, ciphertext[start_index - 8 + j], p)[0]
            elif start_index == 0:
                 xj = xor(0x01 + 7 - i, iv[j], p)[0]  
            Xj = Xj[:j] + bytes([xj]) + Xj[j + 1:]
        c = Xj + ciphertext[start_index: start_index + 8]
        c = run_till_found(c, i, key, iv)
        if start_index != 0:
            p = xor(0x01 + 7 - i, ciphertext[start_index - 8  + i], c[i])[0]
        elif start_index == 0:
            p = xor (0x01 + 7 - i, iv[i], c[i])[0]    
        plaintext_block = plaintext_block[:i] + bytes([p]) + plaintext_block[i + 1:]
    return plaintext_block

def find_all_blocks(ciphertext, key, iv):
    blocks = []
    k = (int((len(ciphertext)) // 8))
    for i in range(k, 0, -1):
        blocks.append(find_block(i, ciphertext, key, iv))
    blocks.reverse()       
    return blocks


def print_plaintext(ciphertext, key, iv):
    #convert ciphertext from string to bytes
    ciphertext = bytes.fromhex(ciphertext)
    #convert key from string to bytes
    key = bytes(key, 'utf-8')
    #convert iv from string to bytes
    iv = bytes.fromhex(iv)

    plaintext = find_all_blocks(ciphertext, key, iv)
    # for p in plaintext:
    #     print_c_in_hexa(p)
    text = bytes()
    for block in plaintext:
        text += block    
    text = unpad(text, DES.block_size)
    text = text.decode()    
    print(text)    
    
print_plaintext(sys.argv[1], sys.argv[2], sys.argv[3])

# print_plaintext(ciphertext, b'poaisfun', b'\x00'*8)
# def main():
#     # print('AA' + sys.argv[1])
#     # print('BB' + sys.argv[2])
#     # print('CC' + sys.argv[3])
#     #print_plaintext(sys.argv[1], sys.argv[2], sys.argv[3])
    

# if __name__ == '__main__':
#     main()




        