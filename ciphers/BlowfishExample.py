from Crypto.Cipher import Blowfish
from Crypto import Random


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
        Constructs the Blowfish object.
        """
        self.bs = Blowfish.block_size
        self.key = b'FSMF73R873YM1872Y21M8721Y7821CR712G'
        self.iv = Random.new().read(self.bs)
        self.encryptor = Blowfish.new(self.key, Blowfish.MODE_CFB, self.iv)
        self.decryptor = Blowfish.new(self.key, Blowfish.MODE_CFB, self.iv)

    def encrypt(self, msg):
        """
        Encrypts the msg.

        PARAMETERS
        ----------
        :param msg : Message to be encrypted
        :type msg : str

        RETURNS
        -------
        :returns encrypted message
        :rtype bytearray
        """
        return self.encryptor.encrypt(msg.encode('utf_8'))

    def decrypt(self, encrypted):
        """
        Decrypts the encrypted message.

        PARAMETERS
        ----------
        :param encrypted : Encrypted message to be decrypted
        :type encrypted : bytearray

        RETURNS
        -------
        :returns decrypted message
        :rtype str
        """
        return self.decryptor.decrypt(encrypted)
