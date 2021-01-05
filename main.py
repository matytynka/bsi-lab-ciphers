from ciphers.RSAExample import RSAExample
from ciphers.BlowfishExample import BlowfishExample
from ciphers.DSAExample import DSAExample
from ciphers.AESExample import AESExample
from ciphers.TwofishExample import TwofishExample
import time


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
                                  "2. Blowfish\n"
                                  "3. DSA\n"
                                  "4. AES\n"
                                  "5. Twofish\n")
            message = input("Please enter a message to encrypt: ")

            if int(cipher_choice) == 1:
                show_cipher(RSAExample(), message)
            elif int(cipher_choice) == 2:
                show_cipher(BlowfishExample(), message)
            elif int(cipher_choice) == 3:
                show_verify(DSAExample(), message)
            elif int(cipher_choice) == 4:
                show_verify(AESExample(), message)
            elif int(cipher_choice) == 5:
                show_cipher(TwofishExample(), b'testowa wiadomos')

        elif int(what_to_do) == 2:
            benchmark()

        elif int(what_to_do) == 3:
            run = False


if __name__ == '__main__':
    main()
