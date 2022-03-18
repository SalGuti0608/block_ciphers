from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

blockLen = AES.block_size

def CBC(info, cipher_key=get_random_bytes(16), iv=get_random_bytes(16)):
	ogLen = len(info)
	paddedInfo = pad(info, blockLen)
	encryptedInfo = cbcEncrypt(cipher_key, paddedInfo, iv, AES.MODE_CBC)
	return encryptedInfo

def pad(information,blockLen):
	info_len = len(information)
	pad = b"\x00" * (blockLen - (info_len % blockLen))
	return (information + pad)

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


