from Crypto.PublicKey import RSA


class RSAKeyGenerator:
    def __init__(self, private_file_name="private.pem", public_file_name="public.pem"):
        self.private_file_name = private_file_name
        self.public_file_name = public_file_name
        self.key = RSA.generate(1024)

    def _create_private_key(self):
        try:
            private_key = self.key.exportKey()
            private_file = open(self.private_file_name, "wb")
            private_file.write(private_key)
            private_file.close()
            print('Private key success created')
        except Exception as e:
            print(e)

    def _create_public_key(self):
        try:
            public_key = self.key.publickey().exportKey()
            public_file = open(self.public_file_name, "wb")
            public_file.write(public_key)
            public_file.close()
            print('Public key success created')
        except Exception as e:
            print(e)

    def generate_all_keys(self):
        self._create_private_key()
        self._create_public_key()