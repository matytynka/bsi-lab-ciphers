from Crypto.Cipher import Blowfish
from Crypto import Random
from struct import pack

class BlowfishExample:
    """
    A class to represent an BlowfishExample.

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
        self.bs = Blowfish.block_size
        self.key = b'FSMF73R873YM1872Y21M8721Y7821CR712G'
        self.iv = Random.new().read(self.bs)
        self.encryptor = Blowfish.new(self.key, Blowfish.MODE_CFB, self.iv)
        self.decryptor = Blowfish.new(self.key, Blowfish.MODE_CFB, self.iv)

    def encrypt(self, msg):
        """
        Encrypts the msg.

        Parameters
        ----------
        msg : str
            Message to be encrypted
        """
        return self.encryptor.encrypt(msg.encode('utf_8'))

    def decrypt(self, encrypted):
        """
        Decrypts the encrypted message.

        Parameters
        ----------
        encrypted : bytearray
            Encrypted message to be decrypted
        """
        return self.decryptor.decrypt(encrypted)