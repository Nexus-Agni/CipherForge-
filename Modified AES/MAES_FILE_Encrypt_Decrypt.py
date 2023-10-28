import os
import time
from StdMAES import MAES

# Set key
key ="mysecretpassword"

# Create AES object
aes = MAES(bytes(key,'utf-8'))

print('\n ----MODIFIED  AES ---')
BLOCK_SIZE=16
in_filename='input.pdf'
s=time.time()
with open(in_filename, 'rb') as infile:
    with open(in_filename+'.enc', 'wb') as outfile:
        while True:
            chunk = infile.read( BLOCK_SIZE)
            if len(chunk) == 0:
                 break
            elif len(chunk) % BLOCK_SIZE != 0:
                chunk += b' ' * (BLOCK_SIZE - len(chunk) % BLOCK_SIZE)
            cip=aes.encrypt(chunk)
            outfile.write(cip)
e=time.time()            
d=e-s
file_size = os.path.getsize(in_filename) # Get the file size in bytes
print(f'input file:{in_filename}\t size:{file_size/1024 :.2f}KB\n')
print(f'encryption time:{d:.4f}seconds')

encryption_time_per_kb = d / (file_size / 1024)
print(f"Encryption time per KB: {encryption_time_per_kb:.4f} seconds")
s=time.time()
with open(in_filename+'.enc', 'rb') as infile:
    with open('input2.pdf', 'wb') as outfile:
        while True:
            chunk = infile.read(BLOCK_SIZE)
            if len(chunk) == 0:
                break
            pla=aes.decrypt(chunk)
            outfile.write(pla)    
e=time.time()            
d=e-s
print(f'decryption time:{d:.4f}seconds')
decryption_time_per_kb = d / (file_size / 1024)
print(f"decryption time per KB: {decryption_time_per_kb:.4f} seconds")

