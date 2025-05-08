from Crypto.Util.number import *
from gmpy2 import *
from string import *


if __name__ == "__main__":
    with open("D:\CTF\Crypto\MTP\c.txt") as f:
        content = f.readlines()

    plains = [long_to_bytes(int(i,16)) for i in content]

    print(len(plains[1]))
    # 27

    flag = "flag{"

    plain_table = ascii_letters + ',.\"? ' 
    flag_table = ascii_letters + digits + "\{\}_"

    #根据明文空间对flag的每一位进行推测
    for i in range(22):
        for c in flag_table:
            tmp = True
            for plain in plains:
                t = chr(plain[5+i]^ord(c))
                if t not in plain_table:
                    tmp = False
                    break
            if tmp:
                flag += c
                break

    # print(flag)
    # print(len(flag))
    #flag{Many_Timeg_Pad_1s_fun}
    #解出来的flag不对，只能恢复原明文试着找找明文了
    
    #恢复原来的明文
    new_plains = [""] * len(plains)

    for i,c in enumerate(flag):
        print(i,c)
        for j,plain in enumerate(plains):
            new_plains[j] += chr(plain[i]^ord(c))

    #new_plain出来也是乱码，不过不要紧，问一下智能的deepseek得到明文
    p = "Couriers or other secure means are not needed to transmit keys, since a message can be enciphered using an encryption key publicly revealed by the intended recipient. Only he can decipher the message, since only he knows the corresponding decryption key. A message can be signed using a privately-held decryption key. Anyone can verify this signature using the corresponding publicly revealed encryption key. Signatures cannot be forged, and a signer cannot later deny the validity of his signature. This has obvious applications in 'electronic mail' and 'electronic funds transfer' systems."

    flag = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(plains[0].decode(), p[:27]))
    print(flag)
    # flag{Many_Time_Pad_1s_fun!}
    

