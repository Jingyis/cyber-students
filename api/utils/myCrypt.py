# import the function from the cryptography

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Hash password

def myCrypt(password, salt):
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    password_bytes = bytes(password, "utf-8")
    hashed_password = kdf.derive(password_bytes)

    return hashed_password.hex()


# create an AES crypt cipher
def aesInstance(nonce_bytes):
    key = "thebestsecretkeyintheentireworld"
    key_bytes = bytes(key, "utf-8")

    aes_ctr_cipher = Cipher(algorithms.AES(key_bytes),
                            mode=modes.CTR(nonce_bytes))
    return aes_ctr_cipher


# ase_encrypt function
def encrypt(aes_ctr_encryptor, plaintext_bytes):
    ciphertext_bytes = aes_ctr_encryptor.update(plaintext_bytes)
    ciphertext = ciphertext_bytes.hex()

    return ciphertext

# ase_decrypt function
def decrypt(aes_ctr_decryptor, ciphertext_bytes):
    plaintext_bytes = aes_ctr_decryptor.update(ciphertext_bytes)
    plaintext = str(plaintext_bytes, "utf-8")

    return plaintext
