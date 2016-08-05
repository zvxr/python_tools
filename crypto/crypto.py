
import argparse
import atexit
import base64
import getpass
import os
import platform

from Crypto.Cipher import AES
from Crypto.Cipher import XOR
from Crypto.Random import random


CIPHER_DEFAULT = "XOR"
CIPHERS = ("XOR",)

PADDING = "".join((chr(i) for i in range(ord('a'), ord('z') + 1)))
PAD_CHAR = "_"


def _aes_cbc_encrypt(data, key):
    # Generate 256-bit random key and 128-bit random IV.
    random_device = Random.new()
    aes_key = random_device.read(32)
    aes_iv = random_device.read(16)

    # TODO -- this needs to hide the key and iv somewhere.

    # Left pad data with a random character to be exact multiple of 16 bytes.
    padding_size = (16 - len(data) % 16) - 1
    pad_char = random.choice(PADDING)
    padded_data = data.ljust(padding_size, pad_char)

    # Generate cipher, encrypt data and return it Base64 encoded.
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    return base64.b64encode(aes_cipher.encrypt(padded_data))


def aes_ecb_encrypt(data, key):
    """Apply AES encryption (ECB mode) to `data`, with `key`.
    `data` and `key` must both be a length of a multiple of 16.
    """
    # Pad the data.
    padded_data = data.ljust(16 - len(data) % 16, PAD_CHAR)

    # Generate cipher, encrypt data and Base64 encode.
    aes_cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(aes_cipher.encrypt(padded_data))


def aes_ecb_decrypt(data, key):
    # Generate cipher, Base64 decode and decrypt data.
    aes_cipher = AES.new(key, AES.MODE_ECB)
    return aes_cipher.decrypt(base64.b64decode(data))


def clear_screen():
    """Executes OS clear screen command."""
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")


def get_data():
    """Collects raw input and returns."""
    data = ""
    print("Please type data. Press ENTER twice or CTRL+C to end.")

    while data[-2:] != "\n\n":
        try:
            data += raw_input()
            data += "\n"
        except KeyboardInterrupt:
            break    

    return data.rstrip("\n")


def get_key():
    """Get and return key using getpass."""
    return getpass.getpass("Please enter key: ")


def xor_encrypt(data, key):
    # Generate cipher, encrypt data and Base64 encode.
    xor_cipher = XOR.new(key)
    return base64.b64encode(xor_cipher.encrypt(data))


def xor_decrypt(data, key):
    # Generate cipher, Base64 decode and decrypt data.
    xor_cipher = XOR.new(key)
    return xor_cipher.decrypt(base64.b64decode(data))


CIPHER_METHODS = {
    "XOR": (xor_encrypt, xor_decrypt)
}


if __name__ == "__main__":
    # Generate parser.
    parser = argparse.ArgumentParser(
        description="""Commandline tool for encrypting/decrypting data."""
    )

    parser.add_argument(
        "--cipher",
        "-c",
        choices=CIPHERS,
        default=CIPHER_DEFAULT,
        help="Cipher to execute. Choices:{}".format(CIPHERS),
        type=str.upper
    )

    parser.add_argument(
        "--clear-on-exit",
        default=True,
        help="When True will clear the screen when script completes.",
        type=bool
    )

    parser.add_argument(
        "--data",
        "-d",
        help="Raw data to encrypt or decrypt. If not provided will be prompted."
    )

    parser.add_argument(
        "--decrypt",
        "-D",
        action="store_true",
        default=False,
        help="When True will decrypt data. When False will encrypt data."
    )

    parser.add_argument(
        "--key",
        "-k",
        help="Key used to encrypt or decrypt. If not provided will be prompted."
    )

    args = parser.parse_args()

    # Take additional actions based on parser.
    if args.clear_on_exit:
        atexit.register(clear_screen)

    if args.data is None:
        args.data = get_data()

    if args.key is None:
        args.key = get_key()

    # Perform encryption/decryption.
    meth = CIPHER_METHODS[args.cipher][args.decrypt]
    print("\nRESPONSE:\n\n{}".format(meth(args.data, args.key)))

    raw_input("Press ENTER key or CTRL+C to complete.")
