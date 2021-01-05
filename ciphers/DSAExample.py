"""
Author: Martyna Świerszcz
Library: PyCryptodome

Following file contains implementation of signing and verifying using Digital Signature Algorithm (DSA).
The algorithm uses a key pair consisting of a public key and a private key. The private key is used to
generate a digital signature for a message, and such a signature can be verified by using the signer's
corresponding public key. The digital signature provides message authentication (the receiver can verify
the origin of the message), integrity (the receiver can verify that the message has not been modified
since it was signed) and non-repudiation (the sender cannot falsely claim that they have not signed
the message).
"""

from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256


class DSAExample:
    """
    A class to represent an DSAExample

    METHODS
    -------
    sign_and_verify(msg):
        Signs and verifies the msg and returns it.
    """
    def __init__(self):
        """
        Constructs the DSAExample object.
        """
        self.key = DSA.generate(2048)
        self.signer = DSS.new(self.key, 'fips-186-3')
        self.verifier = DSS.new(self.key, 'fips-186-3')

    def sign_and_verify(self, msg):
        """
        Verifies and signs the msg.

        PARAMETERS
        ----------
        :param msg : Message to be verified
        :type msg : str
        """
        hash_obj = SHA256.new(msg.encode('utf-8'))
        signature = self.signer.sign(hash_obj)
        try:
            self.verifier.verify(hash_obj, signature)
            print("The message is authentic.")
        except ValueError:
            print("The message is not authentic.")

    def salt_sign_and_verify(self, msg, salt):
        """
        Encrypts the msg with appended salt.

        PARAMETERS
        ----------
        :param msg : Message to be encrypted
        :param salt : salt for encryption
        :type salt str

        """
        hash_obj = SHA256.new((msg+salt).encode('utf-8'))
        signature = self.signer.sign(hash_obj).replace(salt.encode(), "".encode())
        try:
            self.verifier.verify(hash_obj, signature)
            print("The message is authentic.")
        except ValueError:
            print("The message is not authentic.")