from StdMAES import MAES
from OAES import AES
import pandas as pd
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


def avalplain(key,plaintext):
    plainbytes=forward(plaintext)
    keybytes=forward(key)
    c=MAES(keybytes)
    cipher=c.encrypt(plainbytes)
    cipherbits=convert_to_bits(cipher)
    plainbits=hex2bin(plaintext)
    avalbits=[]
    avalcipher=[]
    avaplain=[]
    avaper=[]
    avalbits.append(0)
    avalcipher.append(bin2hex(cipherbits))
    avaplain.append(plaintext)
    avaper.append(0)
    for i in range(128):
        chbits=plainbits
        chbits[i]^=1
        chbytes=convert_to_bytes(chbits)
        chcipher=c.encrypt(chbytes)
        ccipherbits=convert_to_bits(chcipher)
        count=0
        for i in range(128):
            if ccipherbits[i]!=cipherbits[i]:
                count+=1
        avalbits.append(count)
        avalcipher.append(bin2hex(ccipherbits))
        avaplain.append(bin2hex(chbits))
        avaper.append((count/128)*100)
    return avaplain,avalcipher,avalbits,avaper

def avalkey(key,plaintext):
    plainbytes=forward(plaintext)
    keybytes=forward(key)
    c=MAES(keybytes)
    cipher=c.encrypt(plainbytes)
    cipherbits=convert_to_bits(cipher)
    keybits=hex2bin(key)
    avalbits=[]
    avalcipher=[]
    avakey=[]
    avaper=[]
    avalbits.append(0)
    avalcipher.append(bin2hex(cipherbits))
    avakey.append(key)
    avaper.append(0)
    for i in range(128):
        chbits=keybits
        chbits[i]^=1
        chbytes=convert_to_bytes(chbits)
        c=AES(chbytes)
        chcipher=c.encrypt(plainbytes)
        ccipherbits=convert_to_bits(chcipher)
        count=0
        for i in range(128):
            if ccipherbits[i]!=cipherbits[i]:
                count+=1
        avalbits.append(count)
        avalcipher.append(bin2hex(ccipherbits))
        avakey.append(bin2hex(chbits))
        avaper.append((count/128)*100)
    return avakey,avalcipher,avalbits,avaper


key='A9B5ED7585C8B15D7454ED271AA3A3A3'
plaintext='B9B5ED7585C8B15D7454ED271AA3A3A3'
plain,cipherp,bitsp,perp=avalplain(key,plaintext)  
key,cipherk,bitsk,perk=avalkey(key,plaintext)
datak={'key':key,'ciphertext':cipherk,'bits flipped':bitsk,'avalanche effect':perk}
dfk=pd.DataFrame(datak)
dfk.to_excel('avalbitchangekeyMAES.xlsx')
    
datap={'plaintext':plain,'ciphertext':cipherp,'bits flipped':bitsp,'avalanche effect':perp}
dfp=pd.DataFrame(datap)
dfp.to_excel('avalbitchangeplainMAES.xlsx')
    

