"""
Authors: Wojciech Skarbek & Martyna Świerszcz

Following module allows you to test implemented ciphers and benchmark them.
It's a main .py file of 'Cipher' mini-project.

METHODS
-------
show_cipher(cipher, msg):
    Uses chose cipher to encrypt and decrtypt a message and show
    the results.

def show_verify(cipher, msg):
    Uses chose signer to sign and verify a message and show the
    results.

def benchmark():
    Benchmarks RSA, Blowfish, DSA and AES speed.
"""

from ciphers.RSAExample import RSAExample
from ciphers.BlowfishExample import BlowfishExample
from ciphers.DSAExample import DSAExample
from ciphers.AESExample import AESExample
from ciphers.TwofishExample import TwofishExample
import time
import string
import random


def get_random_alphanumeric_string(length):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join((random.choice(letters_and_digits) for i in range(length)))


def show_cipher(cipher, msg):
    """
    Shows a cipher

    PARAMETERS
    ----------
    :param cipher: cipher to show
    :param msg: message to encrypt and decrypt
    """
    print('Message to encrypt: ', msg)
    encrypted = cipher.encrypt(msg)
    print('Encrypted message: ', encrypted)
    decrypted = cipher.decrypt(encrypted)
    print('Decrypted message: ', decrypted)


def show_cipher_salt(cipher, msg):
    """
    Shows a cipher. Also uses salting

    PARAMETERS
    ----------
    :param cipher: cipher to show
    :param msg: message to encrypt and decrypt
    """
    salt = get_random_alphanumeric_string(12)
    print('Salt: ', salt)
    print('Message to encrypt: ', msg)
    encrypted = cipher.salt_encrypt(msg, salt)
    print('Encrypted message: ', encrypted)
    decrypted = cipher.salt_decrypt(encrypted, salt)
    print('Decrypted message: ', decrypted)


def show_verify(cipher, msg):
    """
    Shows a verifier.

    PARAMETERS
    ----------
    :param cipher:
    :param msg:
    """
    print('Message to sign: ', msg)
    cipher.sign_and_verify(msg)


def show_verify_salt(cipher, msg):
    """
    Shows a verifier. Also uses salting

    PARAMETERS
    ----------
    :param cipher:
    :param msg:
    """
    salt = get_random_alphanumeric_string(12)
    print('Salt: ', salt)
    print('Message to sign: ', msg)
    cipher.salt_sign_and_verify(msg, salt)


def benchmark():
    """
    Benchmarks RSA, Blowfish, DSA and AES speed.
    """
    message = "Wiadomosc testowa"
    start = time.time()
    show_cipher(RSAExample(), message)
    stop = time.time()
    rsa_time = stop - start
    start = time.time()
    show_cipher(BlowfishExample(), message)
    stop = time.time()
    blowfish_time = stop - start
    start = time.time()
    show_verify(DSAExample(), message)
    stop = time.time()
    dsa_time = stop - start
    start = time.time()
    show_verify(AESExample(), message)
    stop = time.time()
    aes_time = stop - start
    print("Benchmark done:\n"
          "RSA: ", rsa_time, "s\n",
          "Blowfish: ", blowfish_time, "s\n",
          "DSA: ", dsa_time, "s\n",
          "AES: ", aes_time, "s\n")


def main():
    run = True
    while (run):
        what_to_do = input("What you want to do?\n"
                           "1. Show me a cipher\n"
                           "2. Cipher benchmark\n"
                           "3. Exit\n")

        if int(what_to_do) == 1:
            cipher_choice = input("Which cipher do you want to see?\n"
                                  "1. RSA\n"
                                  "2. RSA + salting\n"
                                  "3. Blowfish\n"
                                  "4. Blowfish + salting\n"
                                  "5. DSA\n"
                                  "6. DSA + salting\n"
                                  "7. AES\n"
                                  "8. AES + salting\n"
                                  "9. Twofish\n")
            message = input("Please enter a message to encrypt: ")

            if int(cipher_choice) == 1:
                show_cipher(RSAExample(), message)
            elif int(cipher_choice) == 2:
                show_cipher_salt(RSAExample(), message)
            elif int(cipher_choice) == 3:
                show_cipher(BlowfishExample(), message)
            elif int(cipher_choice) == 4:
                show_cipher_salt(BlowfishExample(), message)
            elif int(cipher_choice) == 5:
                show_verify(DSAExample(), message)
            elif int(cipher_choice) == 6:
                show_verify_salt(DSAExample(), message)
            elif int(cipher_choice) == 7:
                show_verify(AESExample(), message)
            elif int(cipher_choice) == 8:
                show_verify_salt(AESExample(), message)
            elif int(cipher_choice) == 9:
                show_cipher(TwofishExample(), b'testowa wiadomos')

        elif int(what_to_do) == 2:
            benchmark()

        elif int(what_to_do) == 3:
            run = False


if __name__ == '__main__':
    main()
