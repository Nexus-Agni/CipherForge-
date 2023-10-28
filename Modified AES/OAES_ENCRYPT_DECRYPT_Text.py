from OAES import AES
plaintext=b'Encapsulation is a way to restrict the direct access to some components of an object, so users cannot access state values for all of the variables of a particular object. Encapsulation can be used to hide both data members and data functions or methods associated with an instantiated class or object.'
key=b'mysecretpassword'
c=AES(key)
cipher=c.encrypt(plaintext)
decrypted=c.decrypt(cipher)
print(f'plaintext:{plaintext}\nkey:{key}\nciphertext:{cipher}\nDecrypted text:{decrypted}')