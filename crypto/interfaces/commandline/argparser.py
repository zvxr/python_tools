
import argparse


def add_io_args(parser):
    """Add standard I/O arguments to ArgumentParser."""
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


def add_cipher_args(parser):
    """Add cipher specific arguments to ArgumentParser."""
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
