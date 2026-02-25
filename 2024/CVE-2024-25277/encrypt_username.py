def encrypt(word):
    
    phrase = "e5dl12XYVggihggafXWf0f2YSf2Xngd1"
    a = []
    for idx, char in enumerate(word):
        r = ord(char)
        positioncode = ord(phrase[idx % len(phrase)])
        a.append((240 & positioncode) | ((15 & r) ^ (15 & positioncode)))
        a.append((240 & positioncode) | ((r >> 4) ^ (15 & positioncode)))
    enc_word = "".join(chr(char) for char in a)
    print(enc_word)
    return enc_word


encrypt('admin')
