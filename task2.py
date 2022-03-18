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
    print()
    encodedQuery = submit(inputQuery, intKey, intIv)
    #perform the attack under here!

    aes = AES.new(intKey, AES.MODE_CBC, intIv)
    numBlocks = len(encodedQuery) // blockLen
    plaintext = b''
    xorStr = intIv

    for i in range(0, numBlocks):
        msgIdx = i * blockLen # 
        msg = encodedQuery[msgIdx: msgIdx+blockLen] # block
        # print(len(str(msg)))
        # for c in str(msg):
        #     print(c, end=" ")
        # print()
        decMsg = aes.decrypt(msg) 
        xorMsg = strxor(xorStr, decMsg) # Arrow between decrypt() and xor
        plaintext += xorMsg
        print(f"Decrypted message {len(xorMsg)} after xor: {xorMsg}")

        #temp = strxor(attackBlock, decMsg)
        #changedtext += temp
        #print(f"bitflpped message {len(temp)} after xor: {temp}")
        
        xorMsg = msg    #msg is technically the n-1 ciphertext block
        temp = msg

    plaintext = plaintext.decode().replace('%3D', '=').replace('%3B', ';').replace('%20', ' ')

    plaintext = plaintext.encode()

    verRes = verify(plaintext, intKey, intIv, True)
    print(f"Result: {verRes}")


def submitAndVerify():
    inputQuery = input("Message?: ")
    encodedQuery = submit(inputQuery, intKey, intIv)
    verRes = verify(encodedQuery, intKey, intIv)
    print(verRes)

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
    isAdmin = b';admin=true;'

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

