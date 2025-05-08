from Crypto.Util.number import *
from pwn import *

plain = """**************************"""

flag = 'flag{*********}'

length = len(flag)

block = [plain[i:i + length] for i in range(0, len(plain), length)]
c = []
for i in block:
    result = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(flag, i))
    c.append(result.encode())
b = []
for i in c:
    b.append(hex(bytes_to_long(i)))

with open("c.txt","a") as f:
    for i in b:
        f.write(i+"\n")


