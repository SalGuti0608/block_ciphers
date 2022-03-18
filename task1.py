from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

blockLen = AES.block_size

def pad(information,blockLen):
	info_len = len(information)
	pad = b"\x00" * (blockLen - (info_len % blockLen))
	return (information + pad)

def CBC(info, cipher_key=get_random_bytes(16), iv=get_random_bytes(16)):
	ogLen = len(info)
	paddedInfo = pad(info, blockLen)
	encryptedInfo = cbcEncrypt(cipher_key, paddedInfo, iv, AES.MODE_CBC)
	return encryptedInfo

def cbcEncrypt(key, information, iv, mode=AES.MODE_CBC):
	aes = AES.new(key, mode, iv)
	numBlocks = len(information) // blockLen
	new_info = b''

	xorStr = iv
	for i in range(0, numBlocks):
		msgIdx = i * blockLen
		msg = information[msgIdx:msgIdx+blockLen]
		xorMsg = strxor(xorStr, msg)
		cbcMsg = aes.encrypt(xorMsg)
		new_info += cbcMsg
		xorMsg = cbcMsg

	return new_info 

def decryptCBC(encQuery, cipherKey, iv):
    aes = AES.new(cipherKey, AES.MODE_CBC, iv)
    numBlocks = len(encQuery) // blockLen
    plaintext = b''
    xorStr = iv

    for i in range(0, numBlocks):
        msgIdx = i * blockLen
        msg = encQuery[msgIdx: msgIdx+blockLen]
        decMsg = aes.decrypt(msg)
        xorMsg = strxor(xorStr, decMsg)
        #print(xorMsg)
        #for thing in range(len(msg)):
            #print(f"at index:{thing} with the char: {msg[thing]}")
        plaintext += xorMsg
        xorMsg = msg

    #the below line is how we would get back to our original string!, However we avoid this step with our attack
    #plaintext = urllib.parse.unquote(plaintext, "UTF-8")
    return plaintext

def ECB(info,cipher_key=get_random_bytes(16)):
	ogLen = len(info)
	paddedInfo = pad(info, blockLen)
	encryptedInfo = ecbEncrypt(cipher_key, paddedInfo)
	return encryptedInfo

def ecbEncrypt(key, information, mode=AES.MODE_ECB):
	aes = AES.new(key, mode)
	new_info = b""

	for i in range(0, len(information), blockLen):
		blk = information[i:i+blockLen]
		encBlk = aes.encrypt(blk)
		new_info += encBlk

	return new_info
