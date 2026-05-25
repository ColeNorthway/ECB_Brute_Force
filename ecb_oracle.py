from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests
import json
import time


ascii_set = [
    '}', ' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
    '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '~'
]

def encrypt(plaintext):
    ciphertext = requests.get(f"https://aes.cryptohack.org/ecb_oracle/encrypt/{plaintext}/")
    print(ciphertext)
    ciphertext = (json.loads(ciphertext.content))["ciphertext"]
    return ciphertext

def pkcs_pad(payload):
    if len(payload) % 2 != 0:
        raise ValueError("Bad payload len: Not even")
    padding_size = 16 if len(payload) == 0 else 16-(len(payload))//2     
    padding = ""
    for num in range(padding_size):
        padding += ("0"+hex(padding_size)[2:]) if padding_size < 16 else hex(padding_size)[2:]
    payload += padding
    return payload

def get_padding(size):
    padding = ""
    size //= 2
    for num in range(size):
        padding += ("0"+hex(size)[2:]) if size < 16 else hex(size)[2:]
    return padding

def hex2string(h):
    return "".join([chr(byte) for byte in bytes.fromhex(h)])

def string2hex(s):
    return s.encode('utf-8').hex()

def check_match(num_blocks, response):
    block_size = 32*num_blocks
    return response[:block_size] == response[-block_size:]

def brute_ecb(flag_len):
    # *2 because 2 hex char per 1 byte ~ true size per block is 16
    flag_len *= 2
    block_size = 32
    flag = ""
    brute_len = 0

    while (len(flag)*2) < flag_len:
        # Get init size of padding & add size of current payload to it
        brute_len = (len(flag)*2)+2
        payload_size = (block_size) - (flag_len % block_size)
        payload_size = (32 if payload_size==32 else 32+payload_size) + brute_len

        # Get padding of payload
        padding = get_padding(32-(brute_len%32))
        padding_len = len(padding)

        # Get number of block to compare & len
        num_blocks = ((padding_len+brute_len)//32)

        # Get junk bytes
        junk_bytes = "".join(["0" for i in range(payload_size-brute_len-padding_len)])

        # Main brute force loop
        for a in ascii_set:
            payload = string2hex(a+flag) + padding + junk_bytes
            print(f"[*] PAYLOAD: {payload}")
            ciphertext = encrypt(payload)
            if check_match(num_blocks, ciphertext):
                flag = a+flag
                print(f"[+] MATCH: {flag}")
                break
            
            # Fail case for no inf loop
            if(a=='~'):
                return False
    return flag




def main():
    print(f"[++] FLAG: {brute_ecb(25)}")
    # print(get_padding(2))
    # test_check = "78d7e25ca4b633e5d12d53b815614c5718127eb498a71f33a0324cfe942f1a0998062063b91ebc39cc2e70b1a6b7f14e78d7e25ca4b633e5d12d53b815614c57"
    # print(check_match(1, test_check))

if __name__ == "__main__":
    main()


'''
1) Get the iteration for 1 block at a time
    + Triple check the math
2) Then find out how to do the relap part
    + This is when the end of the payload exceeds 1 block and we have to check second from last
'''