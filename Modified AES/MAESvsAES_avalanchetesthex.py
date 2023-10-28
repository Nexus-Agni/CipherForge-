from StdMAES import MAES
from OAES import AES
import pandas as pd
import random
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


def mavalplain(key,plaintext):
    plainbytes=forward(plaintext)
    keybytes=forward(key)
    c=MAES(keybytes)
    cipher=c.encrypt(plainbytes)
    cipherbits=convert_to_bits(cipher)
    chplainbits=hex2bin(plaintext)
    chplainbits[0]^=1
    chplainbytes=convert_to_bytes(chplainbits)
    chcipher=c.encrypt(chplainbytes)
    chcipherbits=convert_to_bits(chcipher)

    chcipherhex=bin2hex(chcipherbits)
    chplainhex=bin2hex(chplainbits)
    cipherhex=bin2hex(cipherbits)
    count=0
    for i in range(128):
        if chcipherbits[i]!=cipherbits[i]:
            count+=1
    return count,chplainhex,chcipherhex,cipherhex 

def mavalkey(key,plaintext):
    plainbytes=forward(plaintext)
    keybytes=forward(key)
    c=MAES(keybytes)
    cipher=c.encrypt(plainbytes)
    cipherbits=convert_to_bits(cipher)
    chkeybits=hex2bin(key)
    chkeybits[0]^=1
    chkeybytes=convert_to_bytes(chkeybits)
    ch=MAES(chkeybytes)
    chcipher=ch.encrypt(plainbytes)
    chcipherbits=convert_to_bits(chcipher)
    
    chcipherhex=bin2hex(chcipherbits)
    chkeyhex=bin2hex(chkeybits)
    cipherhex=bin2hex(cipherbits)
    count=0
    for i in range(128):
        if chcipherbits[i]!=cipherbits[i]:
            count+=1
    return count,chkeyhex,chcipherhex,cipherhex 

def oavalplain(key,plaintext):
    plainbytes=forward(plaintext)
    keybytes=forward(key)
    c=AES(keybytes)
    cipher=c.encrypt(plainbytes)
    cipherbits=convert_to_bits(cipher)
    chplainbits=hex2bin(plaintext)
    chplainbits[0]^=1
    chplainbytes=convert_to_bytes(chplainbits)
    chcipher=c.encrypt(chplainbytes)
    chcipherbits=convert_to_bits(chcipher)

    chcipherhex=bin2hex(chcipherbits)
    chplainhex=bin2hex(chplainbits)
    cipherhex=bin2hex(cipherbits)
    count=0
    for i in range(128):
        if chcipherbits[i]!=cipherbits[i]:
            count+=1
    return count,chplainhex,chcipherhex,cipherhex 

def oavalkey(key,plaintext):
    plainbytes=forward(plaintext)
    keybytes=forward(key)
    c=AES(keybytes)
    cipher=c.encrypt(plainbytes)
    cipherbits=convert_to_bits(cipher)
    chkeybits=hex2bin(key)
    chkeybits[0]^=1
    chkeybytes=convert_to_bytes(chkeybits)
    ch=AES(chkeybytes)
    chcipher=ch.encrypt(plainbytes)
    chcipherbits=convert_to_bits(chcipher)
    
    chcipherhex=bin2hex(chcipherbits)
    chkeyhex=bin2hex(chkeybits)
    cipherhex=bin2hex(cipherbits)
    count=0
    for i in range(128):
        if chcipherbits[i]!=cipherbits[i]:
            count+=1
    return count,chkeyhex,chcipherhex,cipherhex 



key='75B67BE703FB2628D0D702519A94AC38'
plaintext='FF433B87D5D2EC551CFCF4C66FB3172A'
mkcount,mchangedkey,mkchangedcipher,mkcipherhex =mavalkey(key,plaintext)
mpcount,mchangedplain,mpchangedcipher,mpcipherhex =mavalplain(key,plaintext)
okcount,ochangedkey,okchangedcipher,okcipherhex =oavalkey(key,plaintext)
opcount,ochangedplain,opchangedcipher,opcipherhex =oavalplain(key,plaintext)
        

datap={'plaintext':plaintext,'key':key,'oaes cipher':opcipherhex,'oaes changed plaintext':ochangedplain,
        'oaes cipher due to changed plaintext':opchangedcipher,
       'oaes bits flipped for 1bit change in plaintext':opcount,'oaes avalanche for plaintext in %':(opcount/128)*100,
       'maes cipher':mpcipherhex,'maes changed plaintext':mchangedplain,'maes cipher due to changed plaintext':mpchangedcipher,
       'maes bits flipped for 1bit change in plaintext':mpcount,'maes avalanche for plaintext in %':(mpcount/128)*100}

datak={'plaintext':plaintext,'key':key,'oaes cipher':okcipherhex,'oaes changed key':ochangedkey,
        'oaes cipher due to changed key':okchangedcipher,
       'oaes bits flipped for 1bit change in key':okcount,'oaes avalanche for key %':(okcount/128)*100,
       'maes cipher':mkcipherhex,'maes changed key':mchangedkey,'maes cipher due to changed key':mkchangedcipher,
       'maes bits flipped for 1bit change in key':mkcount,'maes avalanche for key %':(mkcount/128)*100}

print('\n_______Avalanche effect for 1bit change in plaintext_______')
for a,b in datap.items():
    print(f'{a}:{b}')
print('\n_______Avalanche effect for 1bit change in key_______')

for a,b in datak.items():
    print(f'{a}:{b}')    