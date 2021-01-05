"""
Author: Wojciech Skarbek
Library: PyCryptodome

Following file contains implementation of encryption and decryption using RSA
algorithm. RSA is public-key cryptosystem that is used for secure data transmission.
Encryption key is public and the decryption key is kept secret (private).
Messages can be encrypted by anyone, but can only be decoded by someone who
knows the private key.
"""


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

        PARAMETERS
        ----------
        :param msg : Message to be encrypted
        :type msg : str

        RETURNS
        -------
        :returns encrypted message
        :rtype bytearray
        """
        return self.encryptor.encrypt(msg.encode("utf-8"))

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
        return self.decryptor.decrypt(ast.literal_eval(str(encrypted)))

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
