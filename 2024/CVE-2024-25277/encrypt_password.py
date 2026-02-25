
import hashlib

def md5_hash(word):

    phrase = "e5dl12XYVggihggafXWf0f2YSf2Xngd1"
    a = []
    for idx, char in enumerate(word):
        r = ord(char)
        positioncode = ord(phrase[idx % len(phrase)])
        a.append((240 & positioncode) | ((15 & r) ^ (15 & positioncode)))
        a.append((240 & positioncode) | ((r >> 4) ^ (15 & positioncode)))
    enc_word = "".join(chr(char) for char in a)
    
    md5 = hashlib.md5()
    md5.update(enc_word.encode('utf-8'))
    hashed_text = md5.hexdigest()
    
    print(hashed_text)
    return hashed_text



md5_hash('admin')