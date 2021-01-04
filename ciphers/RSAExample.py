from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import ast


class RSAExample:
    """
    A class to represent an RSAExample

    METHODS
    -------
    encrypt(msg):
        Encrypts the msg and returns it.

    decrypt(encrypted):
        Decrypts the encrypted msg and returns it.
    """

    def __init__(self):
        """
        Constructs the RSAExample object.
        """
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.encryptor = PKCS1_OAEP.new(self.public_key)
        self.decryptor = PKCS1_OAEP.new(self.key)

    def encrypt(self, msg):
        """
        Encrypts the msg.

        Parameters
        ----------
        msg : str
            Message to be encrypted
        """
        return self.encryptor.encrypt(msg)

    def decrypt(self, encrypted):
        """
        Decrypts the encrypted message.

        Parameters
        ----------
        encrypted : bytearray
            Encrypted message to be decrypted
        """
        return self.decryptor.decrypt(ast.literal_eval(str(encrypted)))
