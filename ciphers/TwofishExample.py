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
