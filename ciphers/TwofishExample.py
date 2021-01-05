"""
Author: Wojciech Skarbek
Library: Twofish

Following file contains implementation of encryption and decryption using Twofish
algorithm. Twofish is a symmetric-key block cipher with a block size of 128 bits
up to 256. Since Twofish is much slower on modern CPUs, it got completely replaced
by AES and since it never has been patented it's reference implementation has been
placed in the public domain.
"""
from twofish import Twofish


class TwofishExample:
    """
    A class to represent an TwofishExample.

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

        PARAMETERS
        ----------
        :param msg : Message to be encrypted
        :type msg : str

        RETURNS
        -------
        :returns encrypted message
        :rtype bytearray
        """
        return self.tf.encrypt(msg)

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
        return self.tf.decrypt(encrypted).decode()
