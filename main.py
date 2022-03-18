from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

from task1 import ECB, CBC, decryptCBC
from task2 import submitAndVerify 

blockLen = AES.block_size
cipher_key = get_random_bytes(16)
iv = get_random_bytes(16)

def main():
    if len(sys.argv) >= 2:
        infile = sys.argv[1] 
        task1(infile)
    task2()

#perform task1 of the block_ciphers assignment
def task1(inFile):
    try:
        im = Image.open(inFile, mode="r")
    except:
        print(f"Thats is not a valid file.")
        return
    info = im.convert("RGB").tobytes()
    ogLen = len(info)

    ecbInfo = ECB(info,cipher_key)
    cbcInfo = CBC(info,cipher_key,iv)
    #create our new resulting images after encrypting them seperatly
    createNewBMP(im, ecbInfo, ogLen,"ECB")
    createNewBMP(im, cbcInfo, ogLen,"CBC")

def createNewBMP(img,encryptedInfo, infoLen, encType):  #given how we use Pillow, this is how we translate our encoded info back to something that can processed
    newImage = to_RBG(encryptedInfo[:infoLen])
    im2 = Image.new(img.mode, img.size) #let's go pillow for making image processing on our parts easy
    im2.putdata(newImage)
    im2.save(encType + "res.BMP", "BMP")

def to_RBG(information): #some python & list/tuple comprehension magic
    infoLen = len(information)
    r,g,b = tuple(
        map(
            lambda d:
            [information[i] for i in range(0, infoLen) if i % 3 == d], [0,1,2])
        )
    pixels = tuple(zip(r,g,b))
    return pixels

#perform task2 of the block_cipher assignment
def task2():
    submitAndVerify()

if __name__ == "__main__":
    main()