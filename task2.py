from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import urllib.parse #god bless the Python gods for having a built-in function for just about anything
from Crypto.Util.strxor import strxor

from task1 import CBC, decryptCBC

blockLen = AES.block_size
intKey  = b'\x96\x14\xdf\x8f7\xa5\x90tz\x9fBs+s\x01\x06'
intIv = b'A^3l\x1e\x14\x8e\x94\xb6\x077P\x19j\x8c\xca'

#intKey = get_random_bytes(16)
#intIv = get_random_bytes(16)

def submitAndAttack():
    inputQuery = input("[Will be attacked]Message?: ")
    encodedQuery = submit(inputQuery, intKey, intIv)
    #print(encodedQuery)
    #perform the attack under here!

    aes = AES.new(intKey, AES.MODE_CBC, intIv)
    numBlocks = len(encodedQuery) // blockLen
    print(encodedQuery)
    encodedQuery = attack(encodedQuery)
    print(encodedQuery)
    plaintext = b''
    xorStr = intIv

    for i in range(0, 0):
        msgIdx = i * blockLen # 
        msg = encodedQuery[msgIdx: msgIdx+blockLen] # block

        print(f"Block {i}: {msg}")
        # print(len(str(msg)))
        # for c in str(msg):
        #     print(c, end=" ")
        # print()

        decMsg = aes.decrypt(msg) 
        print(f"Decrypted {len(decMsg)} before xor: {decMsg}")
        xorMsg = strxor(xorStr, decMsg) # Arrow between decrypt() and xor
        
        plaintext += xorMsg
        xorMsg = msg

    print(f"plaintext: {plaintext}")

    verRes = verify(encodedQuery, intKey, intIv)
    print(f"Result: {verRes}")


def attack(ciphertext):
    blocks = []
    num_blocks = len(ciphertext) // blockLen

    for i in range(num_blocks - 1): # Removing padding block cuz we can >:)
        blocks.append(ciphertext[i*16: 16 + (i*16)])
    
    l = list(blocks[1])
    print(l)
    l[0] = ord(chr(l[0])) ^ ord("B") ^ ord(";")
    l[6] = ord(chr(l[6])) ^ ord("D") ^ ord("=")
    l[11] = ord(chr(l[11]))^ ord("B") ^ ord(";")
    print(blocks[1])
    print(b''.join(l))
    # TODO return joint ciphertext string

def submitAndVerify():
    inputQuery = input("Message?: ")
    encodedQuery = submit(inputQuery, intKey, intIv)
    verRes = verify(encodedQuery, intKey, intIv)
    print(verRes)

def submit(query, cipherKey, iv):
    prependStr = "userid=456; userdata="
    appendStr = ";session-id=31337"
    # we have to get the 
    fullQuery = prependStr + query + appendStr
    # %3B is the URL encoding of ";" --- %3D is the URL encoding of "="   
    URLquery= urllib.parse.quote(fullQuery) #URL encode our query
    bytesQuery = bytes(URLquery, "UTF-8")
    cbcQuery = CBC(bytesQuery, cipherKey, iv)
    return cbcQuery

def verify(encQuery, cipherKey, iv):
    isAdmin = b";admin=true;"
    #take the encoded query => byte flip it
    #take bit-flipped result => look for "isAdmin" variable within the bit flipped query?
    plaintext = decryptCBC(encQuery, cipherKey, iv)

    #THE UNDERNEATH COMMENT HELPS HELLA FOR DEBUGGING
    #print(plaintext)

    res = isAdmin in plaintext 
    return res

