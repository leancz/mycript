# -*- coding: utf-8 -*-

from cryptography.fernet import Fernet
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class symetric():
    
    def __init__(self, key=None, secrets_directory=''):
        if key is None: key = Fernet.generate_key()
        self.secrets_directory = secrets_directory
        self.key = key
        self.f = Fernet(self.key)

    def write_secret(self, text, file_name):
        destination = self.secrets_directory + file_name
        with open(destination, 'wb') as myfile:
            myfile.write(self.f.encrypt(text))
    
    def read_secret(self, text, file_name):
        source = self.secrets_directory + file_name
        with open(source, 'rb') as myfile:
            clear_text = self.f.decrypt(myfile.read())
        return clear_text
        
    def encrypt(self, text):
        return self.f.encrypt(text)
        
    def decrypt(self, text):
        return self.f.decrypt(text)
        
class asymetric():
    
    def __init__(self):
        pass
 
    
def add_padding(byte_string):
    assert len(byte_string) > 0
    if len(byte_string) < 16:
        padding_length=15-len(byte_string)
        byte_string = byte_string + (bytes([padding_length]) * (padding_length + 1))
        return byte_string
    else:
        raise Exception('byte string is more than 15 characters')

def remove_padding(byte_string):
    if len(byte_string) != 16: raise Exception('byte string is not 16 characters')
    length = byte_string[-1]
    assert length < 15
    for i in byte_string[15-length:-1]:
        if i != length: raise Exception('invalid pad byte')
    return byte_string[0:15 - length]

def bytes_to_blocks(byte_string):
    unencrypted = [byte_string[i:i+15] for i in range(0, len(byte_string), 15)]
    padded = [add_padding(i) for i in unencrypted]
    return padded
    
def ciphertext_to_blocks(byte_string):
    return [byte_string[i:i+16] for i in range(0, len(byte_string), 16)]
    
def ecb_encrypt(byte_string):
    # electronic codebook mode encrypt
    padded = bytes_to_blocks(byte_string)
    sym = symetric()
    encrypted = [sym.encrypt(i) for i in padded]
    return tuple((sym.key, encrypted))

def ecb_decrypt(key, list_of_blocks):
    # electronic codebook mode decrypt
    sym = symetric(key)
    text = b''
    for i in list_of_blocks:
        text = text + remove_padding(sym.decrypt(i))
    return text
    
def generate_initialisation_vector(size=16):
    return os.urandom(size) # This is not cryptographically secure!

def xor(first_byte, second_byte):
    return bytes([ord(chr(first_byte)) ^ ord(chr(second_byte))])
    
def xor_block(first_block, second_block):
    output_block = b''
    for i,item in enumerate(first_block):
        output_block = output_block + xor(item, second_block[i])
    return output_block


def generate_key(size=32):
    return os.urandom(size) # This is not cryptographically secure!

def write_key(file_name, key):
    with open(file_name, 'wb') as f:
        f.write(key)

def read_key(file_name):
    with open(file_name, 'rb') as f:
        key = f.read()
    return key

def block_encrypt(iv, block, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()
    
def block_decrypt(iv, block, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(block) + decryptor.finalize()

def cbc_encrypt(key, byte_string):
    # cyber block chaining encryption
    padded = bytes_to_blocks(byte_string)
    original_iv = generate_initialisation_vector()
    iv = original_iv
    output = b''
    for i in padded:
        ciphertext = block_encrypt(iv, i, key)
        output = output + ciphertext
        iv = ciphertext
    return (original_iv, output)
    
def cbc_decrypt(key, original_iv, byte_string):
    output = b''
    iv = original_iv
    for block in ciphertext_to_blocks(byte_string):
        output = output + remove_padding(block_decrypt(iv, block, key))
        iv = block
    return output
        
        
    
    

"""
>>> import hashlib
>>> m = hashlib.sha1()
>>> m.update(b'this is a test')
>>> m.digest()
b'\xfa&\xbe\x19\xdek\xff\x93\xf7\x0b\xc20\x844\xe4\xa4@\xbb\xad\x02'
>>> m.digest_size
20
>>> m.block_size
64
>>> m = hashlib.sha256()
>>> m.update(b'this is a test')
>>> m.digest()
b'.\x99u\x85H\x97*\x8e\x88"\xadG\xfa\x10\x17\xffr\xf0o?\xf6\xa0\x16\x85\x1fE\xc3\x98s+\xc5\x0c'
>>> m.digest_size
32
>>> m.block_size
64
>>> m.hexdigest()
'2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c'
"""
