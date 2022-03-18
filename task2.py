from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import urllib.parse #god bless the Python gods for having a built-in function for just about anything
from Crypto.Util.strxor import strxor

from task1 import CBC, decryptCBC

blockLen = AES.block_size
#int stands for intial
intKey = get_random_bytes(16)
intIv = get_random_bytes(16)

def submitAndAttack():
    inputQuery = input("[Will be attacked]Message?: ")
    encodedQuery = submit(inputQuery, intKey, intIv)
    print(encodedQuery)
    #perform the attack under here!

    aes = AES.new(intKey, AES.MODE_CBC, intIv)
    numBlocks = len(encodedQuery) // blockLen
    plaintext = b''
    xorStr = intIv

    for i in range(0, numBlocks):
        msgIdx = i * blockLen
        msg = encodedQuery[msgIdx: msgIdx+blockLen]


        print(f"current ciphertext block:\n{msg}")
        for thing in range(len(msg)):
           print(f"at index:{thing} with the bit: {msg[thing]}")

        decMsg = aes.decrypt(msg)
        xorMsg = strxor(xorStr, decMsg)
        plaintext += xorMsg
        '''
        print(f"Decoded-plaintext:{xorMsg}")

        for thing in range(len(xorMsg)):
           print(f"at index:{thing} with the bit: {xorMsg[thing]}")
        '''

        xorMsg = msg

    print(plaintext)

    verRes = verify(encodedQuery, intKey, intIv)
    print(verRes)


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

def verify(encQuery, cipherKey, iv):
    isAdmin = b";admin=true;"
    #take the encoded query => byte flip it
    #take bit-flipped result => look for "isAdmin" variable within the bit flipped query?
    plaintext = decryptCBC(encQuery, cipherKey, iv)

    #THE UNDERNEATH COMMENT HELPS HELLA FOR DEBUGGING
    #print(plaintext)

    res = isAdmin in plaintext 
    return res

