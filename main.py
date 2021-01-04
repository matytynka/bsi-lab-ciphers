from ciphers.RSAExample import RSAExample
from ciphers.BlowfishExample import BlowfishExample
from ciphers.DSAExample import DSAExample


def show_cipher(cipher, msg):
    print('Message to encrypt: ', msg)
    encrypted = cipher.encrypt(msg)
    print('Encrypted message: ', encrypted)
    decrypted = cipher.decrypt(encrypted)
    print('Decrypted message: ', decrypted)


def show_DSA(cipher, msg):
    print('Message to sign: ', msg)
    cipher.sign_and_verify(msg)


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
                                  "3. DSA\n")
            message = input("Please enter a message to encrypt: ")

            if int(cipher_choice) == 1:
                show_cipher(RSAExample(), message)
            elif int(cipher_choice) == 2:
                show_cipher(BlowfishExample(), message)
            elif int(cipher_choice) == 3:
                show_DSA(DSAExample(), message)

        elif int(what_to_do) == 2:
            print("Cipher benchmark")

        elif int(what_to_do) == 3:
            run = False


if __name__ == '__main__':
    main()
