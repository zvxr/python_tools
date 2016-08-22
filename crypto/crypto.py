
import argparse
import atexit
import base64
import getpass
import os
import platform
import subprocess

import classes.ciphers

from Crypto.Cipher import AES
from Crypto.Random import random


CIPHERS = {
    'XOR': classes.ciphers.XORCipher
}
CIPHER_CHOICES = CIPHERS.keys()
CIPHER_DEFAULT = "XOR"

ENCODINGS = {
    'BASE64': (base64.b64encode, base64.b64decode),
    'NONE': (None, None),
}
ENCODING_CHOICES = ENCODINGS.keys()
ENCODING_DEFAULT = "base64"


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


def get_data_from_clipboard():
    """Returns what is in the clipboard."""
    process = subprocess.Popen(['pbpaste'], stdout=subprocess.PIPE, close_fds=True)
    stdout, stderr = process.communicate()
    return stdout.decode('utf-8')


def get_key():
    """Get and return key using getpass."""
    return getpass.getpass("Please enter key: ")


def store_data_in_clipboard(data):
    """Store data in clipboard."""
    process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
    stdoutdata, stderrdata = process.communicate(input=data.encode('utf-8'))


if __name__ == "__main__":
    # Generate parser.
    parser = argparse.ArgumentParser(
        description="""Commandline tool for encrypting/decrypting data."""
    )

    parser.add_argument(
        "--clipboard",
        "-c",
        action="store_true",
        help="Data is pulled/stored in clipboard."
    )

    parser.add_argument(
        "--clear-on-exit",
        "-C",
        action="store_true",
        help="When True will clear the screen when script completes."
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
        "--encoding",
        "-e",
        choices=ENCODING_CHOICES,
        default=ENCODING_DEFAULT,
        help="Encoding to apply to encrypted data or data when decrypting. Choices:{}".format(
            ENCODING_CHOICES
        ),
        type=str.upper
    )

    parser.add_argument(
        "--key",
        "-k",
        help="Key used to encrypt or decrypt. If not provided will be prompted."
    )

    parser.add_argument(
        "--mode",
        "-m",
        choices=CIPHER_CHOICES,
        default=CIPHER_DEFAULT,
        help="Cipher to execute. Choices:{}".format(CIPHER_CHOICES),
        type=str.upper
    )

    args = parser.parse_args()

    # Take additional actions based on parser.
    if args.clear_on_exit:
        atexit.register(clear_screen)

    if args.clipboard:
        args.data = get_data_from_clipboard()

    if args.data is None:
        args.data = get_data()

    if args.key is None:
        args.key = get_key()

    # Perform encryption/decryption.
    cipher = CIPHERS[args.mode](args.key)

    if args.encoding:
        cipher.set_encoding(*ENCODINGS[args.encoding])

    if args.decrypt:
        response = cipher.decrypt(args.data)
    else:
        response = cipher.encrypt(args.data)

    # Store results.
    if args.clipboard:
        store_data_in_clipboard(response)
        print("\nRESPONSE has been stored in clipboard.\n\n")
    else:
        print("\nRESPONSE:\n\n{}".format(response))

    # Require user acknowledgement before screen clear.
    if args.clear_on_exit:
        raw_input("Press ENTER key or CTRL+C to complete.")
