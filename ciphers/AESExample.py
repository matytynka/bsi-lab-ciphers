from Crypto.Cipher import AES

class AESExample:

    def __init__(self):
        self.key = b'FSMF73R873YM187R'
        self.signer = AES.new(self.key, AES.MODE_EAX)
        self.verifier = AES.new(self.key, AES.MODE_EAX, nonce=self.signer.nonce)


    def sign_and_verify(self, msg):
        ciphertext, tag = self.signer.encrypt_and_digest(msg.encode('utf-8'))
        plaintext = self.verifier.decrypt(ciphertext)
        try:
            self.verifier.verify(tag)
            print("The message is authentic: ", plaintext)
        except ValueError:
            print("Key incorrect or message corrupted")