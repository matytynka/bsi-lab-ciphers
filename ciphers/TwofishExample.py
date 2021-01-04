from twofish import Twofish
from Crypto import Random
from struct import pack

class TwofishExample:
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
        Constructs the TwofishExample object.
        """
        self.key = b'FSMF73R873YM1872Y'
        self.tf = Twofish(self.key)

    def encrypt(self, msg):
        """
        Encrypts the msg.

        Parameters
        ----------
        msg : str
            Message to be encrypted
        """
        return self.tf.encrypt(msg)

    def decrypt(self, encrypted):
        """
        Decrypts the encrypted message.

        Parameters
        ----------
        encrypted : bytearray
            Encrypted message to be decrypted
        """
        return self.tf.decrypt(encrypted).decode()