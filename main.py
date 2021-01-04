from ciphers.RSAExample import RSAExample
from ciphers.BlowfishExample import BlowfishExample


def showCipher(cipher, msg):
    print('Message to encrypt: ', msg)
    encrypted = cipher.encrypt(msg)
    print('Encrypted message: ', encrypted)
    decrypted = cipher.decrypt(encrypted)
    print('Decrypted message: ', decrypted)


def main():
    #showCipher(RSAExample(), 'Testowa wiadomosc')
    showCipher(BlowfishExample(), 'Testowa wiadomosc')


if __name__ == '__main__':
    main()