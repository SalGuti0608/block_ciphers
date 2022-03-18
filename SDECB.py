from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

blockLen = AES.block_size

def ECB(info,cipher_key=get_random_bytes(16)):
	ogLen = len(info)
	paddedInfo = pad(info, blockLen)
	encryptedInfo = ecbEncrypt(cipher_key, paddedInfo)
	return encryptedInfo

def pad(information,blockLen):
	info_len = len(information)
	pad = b"\x00" * (blockLen - (info_len%blockLen))
	return (information + pad)

def ecbEncrypt(key, information, mode=AES.MODE_ECB):
	aes = AES.new(key, mode)

	new_info = b""

	for i in range(0, len(information), blockLen):
		blk = information[i:i+blockLen]
		encBlk = aes.encrypt(blk)
		new_info += encBlk

	return new_info

