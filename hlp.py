L:qfrom operator import xor
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import urllib.parse
from base64 import b64encode
from base64 import b64decode
from Crypto.Util.strxor import strxor


def pad7(data):
    return data +  b"\x00" * (16 - (len(data) % 16))

def CBC(data):
    data = pad7(data)
    key = get_random_bytes(16)
    IV = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)

    length = len(data)

    numBlocks = length // 16

    totalEncrypt = b''

    for i in range(0, numBlocks):
        message = data[i*16: i*16 + 16]
        xormessage = strxor(IV, message)
        encryptMessage = cipher.encrypt(xormessage)
        totalEncrypt += encryptMessage
        IV = encryptMessage

    return key, IV, totalEncrypt

def submit():
    p1 = "userid=456;userdata="
    p2 = ";session-id=31337"
    text = input ("Enter a user data: ")
    # url encoding
    text = urllib.parse.quote(text)
    combined = p1 + text + p2
    print(combined)
    return CBC(bytes(combined, 'UTF-8'))

def verify():
    key, IV, encrypted = submit()
    #newEncry = byteFlipAttack(encrypted)
    text = decryptData(encrypted, key, IV)
    print("decrypted", text)
    if ";admin=true;" in str(text):
        print("True")
        return True
    print("False")
    return False

def imageProc():
    # Open a file
    in_img = open("cp-logo.bmp", "rb")
    out_img = open("cp_encrypted.bmp", "wb")

    # Read the files originalText
    originalText = in_img.read()

    originalHeader = originalText[0:54]
    data = originalText[54:]

    # Padding the string
    data = pad7(str(data))
    data = str.encode(data)
    # Encryption of the string
    encrypt = CBC(data)
    out_img.write(originalHeader)
    out_img.write(encrypt)

def decryptData(data, key, iv):
   cipher = AES.new(key, AES.MODE_ECB)

   length = len(data)

   # 16 bytes in a block. And length is given in bytes
   numBlocks = length // 16

   # initializing variables
   totalDecrypt = b''

   # Decrypt with CBC
   for i in range(0, numBlocks):
      message = data[i*16: i*16 + 16]
      decryptMessage = cipher.decrypt(message)
      xormessage = strxor(iv, decryptMessage)
      totalDecrypt += xormessage
      iv = message
   return totalDecrypt

def byteFlipAttack(ciphertext):
    chrs = []
    i = 0
    while i*16 <= len(ciphertext):
        chrs.append(ciphertext[i*16: 16 + (i*16)])
        i += 1
    chrs.remove(chrs[3])

    attack_on_block = chrs[1]
    list1 = list(attack_on_block)
    list1[0] = chr(ord(list1[0]) ^ ord("B") ^ ord(";"))
    list1[6] = chr(ord(list1[6]) ^ ord("D") ^ ord("="))
    list1[11] = chr(ord(list1[11]) ^ ord("B") ^ ord(";"))
    chrs[1] = ''.join(list1)
    return ''.join(chrs)


def bitFlip( pos, bit, data):
    raw = b64decode(data)

    list1 = list(raw)
    list1[pos] = chr(ord(list1[pos])^bit)
    raw = ''.join(list1)
    return b64encode(raw)

def setbyte(ciphertext, char, byteNum, key, iv):
    print("cipher", ciphertext)
    print(type(ciphertext))
    # decrypt the data to get the correct ending term
    decrypt = ""
    decrypt = decryptData(ciphertext, key, iv)
    binaryChar = ord(char)
    print("setbyte ", decrypt)
    print(strxor(decrypt, ciphertext))
    # currentByte is the byte that will ultimately be changed in the decrypting
    currentByte = decrypt[byteNum:byteNum + 1]
    print("current byte ", decrypt[byteNum:byteNum + 1])

    # changeByte is the byte 16 spaces below the currentByte which will be changed such that currentByte can ultimately be changed in the decrypting
    changeByte = ciphertext[byteNum - 16:byteNum - 15]
    print("changebyte ", changeByte)

    xormask = binaryChar ^ ord(currentByte)
    print("xormask ", chr(xormask))

    flipbyte = int(xormask) + ord(changeByte)

    # truncate the flipbyte
    flipbyte &= 0b11111111
    print(flipbyte)

    newString = b''

    newString += ciphertext[0:byteNum - 16] + str.encode(chr(flipbyte)) + ciphertext[byteNum - 15:]
    print(newString)
    return newString

verify()
