"""
Author: Martyna Świerszcz
Library: PyCryptodome

Following file contains implementation of signing and verifying using Advanced Encryption Standard (AES).
AES is based on a design principle known as a substitution–permutation network, and is efficient in both
software and hardware.[9] Unlike its predecessor DES, AES does not use a Feistel network. AES is a variant
of Rijndael, with a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits. By contrast,
Rijndael per se is specified with block and key sizes that may be any multiple of 32 bits, with a minimum of
128 and a maximum of 256 bits.
"""

from Crypto.Cipher import AES


class AESExample:
    """
    A class to represent an RSAExample

    METHODS
    -------
    encrypt(msg):
        Signs the msg and returns it.

    sign_and_verify(msg):
        Signs and verifies the msg and returns it.
    """
    def __init__(self):
        """
        Constructs the RSAExample object.
        """
        self.key = b'FSMF73R873YM187R'
        self.signer = AES.new(self.key, AES.MODE_EAX)
        self.verifier = AES.new(self.key, AES.MODE_EAX, nonce=self.signer.nonce)

    def sign_and_verify(self, msg):
        """
        Verifies and signs the msg.

        PARAMETERS
        ----------
        :param msg : Message to be verified
        :type msg : str
        """
        ciphertext, tag = self.signer.encrypt_and_digest(msg.encode('utf-8'))
        plaintext = self.verifier.decrypt(ciphertext)
        try:
            self.verifier.verify(tag)
            print("The message is authentic: ", plaintext)
        except ValueError:
            print("Key incorrect or message corrupted")

    def salt_sign_and_verify(self, msg, salt):
        """
        Encrypts the msg with appended salt.

        PARAMETERS
        ----------
        :param msg : Message to be encrypted
        :param salt : salt for encryption
        :type salt str

        """
        ciphertext, tag = self.signer.encrypt_and_digest((msg+salt).encode('utf-8'))
        plaintext = self.verifier.decrypt(ciphertext).replace(salt.encode(), "".encode())
        try:
            self.verifier.verify(tag)
            print("The message is authentic: ", plaintext)
        except ValueError:
            print("Key incorrect or message corrupted")
