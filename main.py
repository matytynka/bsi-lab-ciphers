from ciphers.RSAExample import RSAExample
from ciphers.Blowfish import BlowfishExample

def showRSA(msg):
    rsa = RSAExample()
    print('Message to encrypt: ', msg)
    encrypted = rsa.encrypt(msg)
    print('Encrypted message: ', encrypted)
    decrypted = rsa.decrypt(encrypted)
    print('Decrypted message: ', decrypted)


def main():
    showRSA('Testowa wiadomosc')

if __name__ == '__main__':
    main()