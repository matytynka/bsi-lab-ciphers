"""
Author: Wojciech Skarbek
Library: PyCryptodome

Following file contains implementation of encryption and decryption using Blowfish
algorithm. Blowfish is a symmetric-key block cipher. These days it's being replaced
by much more modern AES. Nonetheless it's still used since it has good encryption
rate in software and still no effective cryptanalysis of it has been found.
"""
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

    def salt_encrypt(self, msg, salt):
        """
        Encrypts the msg with appended salt.

        PARAMETERS
        ----------
        :param msg : Message to be encrypted
        :param salt : salt for encryption
        :type salt str

        RETURNS
        -------
        :returns encrypted message
        :rtype bytearray
        """
        return self.encrypt(msg+salt)

    def salt_decrypt(self, encrypted, salt):
        """
        Decrypts the encrypted message with appended salt.

        PARAMETERS
        ----------
        :param encrypted : Encrypted message to be decrypted
        :type encrypted : bytearray
        :param salt : salt for encryption
        :type salt str

        RETURNS
        -------
        :returns decrypted message
        :rtype str
        """
        return self.decrypt(encrypted).replace(salt.encode(), "".encode())