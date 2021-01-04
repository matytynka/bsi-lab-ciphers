from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

class DSAExample:
    """
    A class to represent an RSAExample

    METHODS
    -------
    encrypt(msg):
        Signs the msg and returns it.

    decrypt(encrypted):
        Verifies the encrypted msg and returns it.
    """
    def __init__(self):
        """
        Constructs the RSAExample object.
        """
        self.key = DSA.generate(2048)
        self.signer = DSS.new(self.key, 'fips-186-3')
        self.verifier = DSS.new(self.key, 'fips-186-3')

    def sign_and_verify(self, msg):
        """
        Verifies and signs the msg.

        Parameters
        ----------
        msg : str
            Message to be encrypted
        """
        hash_obj = SHA256.new(msg.encode('utf-8'))
        signature = self.signer.sign(hash_obj)
        try:
            self.verifier.verify(hash_obj, signature)
            print("The message is authentic.")
        except ValueError:
            print("The message is not authentic.")
