from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

blockLen = AES.block_size

def CBC(info, cipher_key=get_random_bytes(16), iv=get_random_bytes(16)):
	ogLen = len(info)
	paddedInfo = pad(info, blockLen)
	mode = AES.MODE_CBC

	encryptedInfo = cbcEncrypt(cipher_key, paddedInfo, iv)
	return encryptedInfo

def pad(information,blockLen):
	info_len = len(information)
	pad = b"\x00" * (blockLen - (info_len%blockLen))
	return (information + pad)

def cbcEncrypt(key, information, iv, mode=AES.MODE_CBC):
	aes = AES.new(key, mode, iv)

	'''
	for i in range(0, len(information), blockLen):
		blk = information[i:i+blockLen]
		encBlk = aes.encrypt(blk)
		new_info += encBlk
	'''

	new_info = aes.encrypt(information)

	return new_info

