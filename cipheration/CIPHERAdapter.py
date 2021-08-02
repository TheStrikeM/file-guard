from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from colorama import Fore
import os


class CIPHERAdapter:
    def __init__(self, ext=".bin"):
        self.ext = ext

    def encrypt(self, file):
        f = open(file, "rb")
        data = f.read();
        f.close()

        file_out = open(str(file) + self.ext, "wb")

        recipient_key = RSA.import_key(open("public.pem").read())
        session_key = get_random_bytes(16)

        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
        print(Fore.GREEN + file + " has encrypted")
        os.remove(file)

    def encrypt_walk(self, dir):
        for name in os.listdir(dir):
            path = os.path.join(dir, name)
            if os.path.isfile(path):
                self.encrypt(path)
            else:
                self.encrypt_walk(path)

    def decrypt(self, file):

        file_in = open(file, "rb")
        file_out = open(str(file[:-4]), "wb")
        private_key = RSA.import_key(open("private.pem").read())

        enc_session_key, nonce, tag, ciphertext = \
            [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        file_out.write(data)
        print(Fore.GREEN + file + " has decrypted")
        os.remove(file)

    def decrypt_walk(self, dir):
        for name in os.listdir(dir):
            path = os.path.join(dir, name)
            if os.path.isfile(path):
                self.decrypt(path)
            else:
                self.decrypt_walk(path)
