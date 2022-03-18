from pydoc import plain
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor
import urllib.parse #god bless the Python gods for having a built-in function for just about anything
import binascii

from task1 import CBC, decryptCBC

blockLen = AES.block_size
intKey = b'\x96\x14\xdf\x8f\xa5\x90\x9f\x01\x06\xcf\x15\x89\x0c\xa7\x17\xd0'
intIv = b'\x14\x1e\x14\x8e\x94\xb6\xa5\xdf\x14\x1e\x14\x8e\x94\xb6\xa5\xdf'

#intKey = get_random_bytes(16)
#intIv = get_random_bytes(16)

def submitAndAttack():
    inputQuery = input("[Will be attacked]Message?: ")
    encodedQuery = submit(inputQuery, intKey, intIv)
    #perform the attack under here!

    aes = AES.new(intKey, AES.MODE_CBC, intIv)
    numBlocks = len(encodedQuery) // blockLen
    plaintext = b''
    xorStr = intIv


    for i in range(0, numBlocks):
        msgIdx = i * blockLen # 
        msg = encodedQuery[msgIdx: msgIdx+blockLen] # block

        if i == 0:
            flippedC0 = attack(encodedQuery)
            attackMsg = flippedC0[0]
            Msg = attackMsg 


        decMsg = aes.decrypt(msg) 
        xorMsg = strxor(xorStr, decMsg) # Arrow between decrypt() and xor
        plaintext += xorMsg
        
        xorMsg = msg    #msg is technically the n-1 ciphertext block
        temp = msg

    plaintext = plaintext.decode().replace('%3D', '=').replace('%3B', ';').replace('%20', ' ')
    plaintext = plaintext.encode()

    verRes = verify(plaintext, intKey, intIv, True)
    print(f"Verify-Result: {verRes}")


def attack(ciphertext):
    blocks = []
    num_blocks = len(ciphertext) // blockLen

    for i in range(num_blocks): # Removing padding block cuz we can >:)
        blocks.append(ciphertext[i*16: 16 + (i*16)])
    
    l = list(blocks[0])
    #becase we want to attack the information starting at block2, we have to attack block1

    l[0] = ord(chr(l[0])) ^ ord("B") ^ ord(";")
    l[6] = ord(chr(l[6])) ^ ord("D") ^ ord("=")
    l[11] = ord(chr(l[11]))^ ord("B") ^ ord(";")

    blocks[0] = l #put back our intial ciphetext block

    res = b""
    for block in blocks:
        for c in block:
            temp = str(c)
            temp2 = temp.encode("UTF-8")
            res += temp2

    return blocks 

def submitAndVerify():
    inputQuery = input("Message?: ")
    encodedQuery = submit(inputQuery, intKey, intIv)
    verRes = verify(encodedQuery, intKey, intIv, False)
    print(f"Verify-Result: {verRes}")

def submit(query, cipherKey, iv):
    prependStr = "userid=456;userdata="
    appendStr = ";session-id=31337"
    # we have to get the 
    fullQuery = prependStr + query + appendStr
    # %3B is the URL encoding of ";" --- %3D is the URL encoding of "="   
    URLquery= urllib.parse.quote(fullQuery) #URL encode our query
    bytesQuery = bytes(URLquery, "UTF-8")
    cbcQuery = CBC(bytesQuery, cipherKey, iv)
    return cbcQuery

def verify(encQuery, cipherKey, iv, attacked=False):
    isAdmin = b'admin=true;'

    #take the encoded query => byte flip it
    #take bit-flipped result => look for "isAdmin" variable within the bit flipped query?
    if not attacked:
        plaintext = decryptCBC(encQuery, cipherKey, iv)
    else:
        plaintext = encQuery
    #THE UNDERNEATH COMMENT HELPS HELLA FOR DEBUGGING
    #print(plaintext)

    res = isAdmin in plaintext 
    return res

