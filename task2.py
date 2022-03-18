from pydoc import plain
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
        xorMsg = msg

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
    prependStr = "userid=456; userdata="
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

