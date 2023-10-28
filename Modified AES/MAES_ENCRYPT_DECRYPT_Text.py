from StdMAES import MAES
from key import key
from plaintext import plaintext

Encrypt_Cipher = []
Decrypt_Cipher = []

if len(plaintext) <= 16:
    print(plaintext)
    c = MAES(key)
    cipher = c.encrypt(plaintext)
    decrypted = c.decrypt(cipher)
else:
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i+16]

        if len(chunk) == 16:
            c = MAES(key)
            cipher = c.encrypt(chunk)
            Encrypt_Cipher.append(cipher)
            decrypted = c.decrypt(cipher)
            Decrypt_Cipher.append(decrypted)
        else:
            c = MAES(key)
            chunk_padded = chunk.ljust(16, b'\x00')
            cipher = c.encrypt(chunk_padded)
            Encrypt_Cipher.append(cipher)
            decrypted = c.decrypt(cipher)
            decrypted = decrypted.rstrip(b'\x00')
            Decrypt_Cipher.append(decrypted)

if len(plaintext) <= 16:
    print(f'plaintext:{plaintext}\nkey:{key}\nciphertext:{cipher}\nDecrypted text:{decrypted}')
else:
    Encryption = b''.join(Encrypt_Cipher)  
    Decryption = b''.join(Decrypt_Cipher)  
    print(f'plaintext:{plaintext}\nkey:{key}\nciphertext:{Encryption}\nDecrypted text:{Decryption}')
