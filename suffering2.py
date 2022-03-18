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
    print(encodedQuery)
    '''
    print()
    print(f"Len of Query: {len(encodedQuery)}, numBlocks: {numBlocks}")
    print()
    for i in encodedQuery:
        print(f"num:{i}, chr:{chr(i)}")
    '''

    plaintext = b''
    xorStr = intIv
    changedtext = b''
    #slight modification of IntIV
    attackBlock = b'\x1e\x1e\x14\x8e\x94\xb6\xa5\xdf\x14\x1e\x14\x8e\x94\xb6\xa5\xdf'

    attack(encodedQuery)

    for i in range(0, numBlocks):
        msgIdx = i * blockLen # 
        msg = encodedQuery[msgIdx: msgIdx+blockLen] # block

        #OG first block = b"\xb3\xf5zfR\x1c\xd7'\xbe\xbfR\xd1x%\xc9i" 
        # Originally, this will be the first block of ciphertext 
        if i == 0:
            print(msg)
      #      msg = b"\xb3\xf5zfR\x1c\xd7'\xae\xbfR\xb60%\xc9i" #this is 5 blocks of information


        #elif i == 1:
        #   msg = b'\xeeJ\x95\xa2\x90\xd8\x81\x8f|\x83L\xbf}\x1f\x04|'
        
        t1 = binascii.hexlify(msg)
        t2 = binascii.unhexlify(t1)

        print(f"Block {i}")
        decMsg = aes.decrypt(msg) 
        #print(f"Decrypted message {len(decMsg)} before xor: {decMsg}")

        t = binascii.hexlify(decMsg)
        #print(f"Decrypt hexlified {len(t)} before xor: {t}")
        y = binascii.unhexlify(t)
        #print(f"Decpt unhexlified {len(y)} before xor: {y}")

        xorMsg = strxor(xorStr, y)

        plaintext += xorMsg
        print(f"Decrypted message {len(xorMsg)} after xor: {xorMsg}")

        #temp = strxor(attackBlock, decMsg)
        #changedtext += temp
        #print(f"bitflpped message {len(temp)} after xor: {temp}")
        
        xorMsg = msg    #msg is technically the n-1 ciphertext block
        temp = msg

    print(f"plaintext: {plaintext}")
    print(f"changedText: {changedtext}")


    attacked = True
    verRes = verify(changedtext, intKey, intIv, attacked)
    print(f"Result: {verRes}")


def byteFlipCiphertext(encQuery, attackBlock):
    pass


def attack(ciphertext):
    blocks = []
    num_blocks = len(ciphertext) // blockLen

    for i in range(num_blocks): # Removing padding block cuz we can >:)
        blocks.append(ciphertext[i*16: 16 + (i*16)])
    
    l = list(blocks[0])

    l[0] = ord(chr(l[0])) ^ ord("B") ^ ord(";")
    l[6] = ord(chr(l[6])) ^ ord("D") ^ ord("=")
    l[11] = ord(chr(l[11]))^ ord("B") ^ ord(";")

    blocks[0] = 1 #put back our intial ciphetext block

    res = b""
    for block in blocks:
        print(len(block))
        for c in block:
            temp = str(c)
            temp2 = temp.encode("UTF-8")
            res += temp2

    return res


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
    isAdmin = b";admin=true;"
    #take the encoded query => byte flip it
    #take bit-flipped result => look for "isAdmin" variable within the bit flipped query?
    if attacked == False:
        plaintext = decryptCBC(encQuery, cipherKey, iv)
        res = isAdmin in plaintext 
    else:
        test = b"sossion"
        res = test in encQuery
    return res

