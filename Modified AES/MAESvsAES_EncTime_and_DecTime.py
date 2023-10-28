from StdMAES import MAES
from OAES import AES
import pandas as pd

import time
def convert_to_bytes(bits):
    bytes_list = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        byte_str = ''.join([str(bit) for bit in byte_bits])
        byte = int(byte_str, 2)
        bytes_list.append(byte)
    return bytes(bytes_list)

def convert_to_bits(bytes_obj):
    bits = []
    for b in bytes_obj:
        bin_str = format(b, '08b')
        bits.extend([int(x) for x in list(bin_str)])
    return bits
def bin2hex(s):

    mp = {"0000": '0',

          "0001": '1',

          "0010": '2',

          "0011": '3',

          "0100": '4',

          "0101": '5',

          "0110": '6',

          "0111": '7',

          "1000": '8',

          "1001": '9',

          "1010": 'A',

          "1011": 'B',

          "1100": 'C',

          "1101": 'D',

          "1110": 'E',

          "1111": 'F'}

    hexa = ""
    s=tuple(s)
    
    for i in range(0, len(s), 4):
        ch=""
        ch=str(s[i]) 
        ch=ch+str(s[i+1]) 
        ch=ch+str(s[i+2]) 
        ch=ch+str(s[i+3]) 
        hexa = hexa + mp[ch]
    return str(hexa) 
    
def hex2bin(s):

    mp = {'0': "0000",

          '1': "0001",

          '2': "0010",

          '3': "0011",

          '4': "0100",

          '5': "0101",

          '6': "0110",

          '7': "0111",

          '8': "1000",

          '9': "1001",

          'A': "1010",

          'B': "1011",

          'C': "1100",

          'D': "1101",

          'E': "1110",

          'F': "1111"}

    bits=[]
    for i in range(len(s)):
        bin_str = mp[s[i]]
        bits.extend([int(x) for x in list(bin_str)])
    return bits    

def forward(a):
    bits=hex2bin(a)
    abytes=convert_to_bytes(bits)
    return abytes
def nsplit(s, n):#Split a list into sublists of size "n"
    return [s[k:k+n] for k in range(0, len(s), n)]
oenc=[]
odec=[]
menc=[]
mdec=[]
bl=[]
for b in range(0,5001,200):
    plaintext='FF433B87D5D2EC551CFCF4C66FB3172A'
    key='75B67BE703FB2628D0D702519A94AC38'
    plaintexts=plaintext*b
    bl.append(b)

    s=time.time()
    plainblocks=nsplit(plaintexts,32)
    ciphers=[]
    for e in range(len(plainblocks)):
        plain=forward(plainblocks[e])
        ke=forward(key)
        c=MAES(ke)
        cipher=c.encrypt(plain)
        cibits=convert_to_bits(cipher)
        cihex=bin2hex(cibits)
        ciphers.append(cihex)
    ciphertext=''.join(ciphers)    
    e=time.time()
    menc.append(e-s)

    s=time.time()
    ciphersblock=nsplit(ciphertext,32)
    dec=[]
    for d in range(len(ciphersblock)):
        ci=forward(ciphersblock[d])
        ke=forward(key)
        c=MAES(ke)
        decrypted=c.decrypt(ci)
        debits=convert_to_bits(decrypted)
        dehex=bin2hex(debits)
        dec.append(dehex)
    decryptedtext=''.join(dec)    
    d=nsplit(decryptedtext,32)
    for i in range(len(d)):
        if(d[i]!=plainblocks[i]):
            print('failed decryption')
            break
    print(f'{b}block MAES passed')
    e=time.time()
    mdec.append(e-s)


    s=time.time()
    plainblocks=nsplit(plaintexts,32)
    ciphers=[]
    for e in range(len(plainblocks)):
        plain=forward(plainblocks[e])
        ke=forward(key)
        c=AES(ke)
        cipher=c.encrypt(plain)
        cibits=convert_to_bits(cipher)
        cihex=bin2hex(cibits)
        ciphers.append(cihex)
    ciphertext=''.join(ciphers)    
    e=time.time()
    oenc.append(e-s)

    s=time.time()
    ciphersblock=nsplit(ciphertext,32)
    dec=[]
    for d in range(len(ciphersblock)):
        ci=forward(ciphersblock[d])
        ke=forward(key)
        c=AES(ke)
        decrypted=c.decrypt(ci)
        debits=convert_to_bits(decrypted)
        dehex=bin2hex(debits)
        dec.append(dehex)
    decryptedtext=''.join(dec)    
    d=nsplit(decryptedtext,32)
    for i in range(len(d)):
        if(d[i]!=plainblocks[i]):
            print('failed decryption')
            break
    print(f'{b}block OAES passed')
    e=time.time()
    odec.append(e-s)


data={'BLOCKSIZE':bl,'OAES ENCRYPTION TIME':oenc,'OAES DECRYPTION TIME':odec,'MAES ENCRYPTION TIME':menc,'MAES DECRYPTION TIME':mdec}
df=pd.DataFrame(data)
df.to_excel('performance.xlsx')
    

    

