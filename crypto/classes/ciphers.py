
import base64

from Crypto import Random
from Crypto.Cipher import AES, XOR


# Base Classes.
class CryptoCipher(object):
    """Base Class for Ciphers."""
    def __init__(self, key=None):
        self._key = key

    def __repr__(self):
        return "{} key {} set.".format(
            self.__class__,
            "is" if self._key is not None else "is not"
        )

    @property
    def key(self):
        if self._key is not None:
            return self._key
        raise Exception("Key is not set.")

    @key.setter
    def key(self, value):
        self._key = value

    def encrypt(self, data):
        raise NotImplemented("Method not defined.")

    def decrypt(self, data):
        raise NotImplemented("Method not defined.")


class BlockCipher(CryptoCipher):
    """Base Class for Block Ciphers."""
    def __init__(self, key=None, iv=None):
        super(BlockCipher, self).__init__(key)
        self._iv = iv

    def __repr__(self):
        return "{} key {} set, IV {} set.".format(
            self.__class__,
            "is" if self._key is not None else "is not",
            "is" if self._iv is not None else "is not"
        )

    @property
    def iv(self):
        if self._iv is not None:
            return self._iv
        raise Exception("IV is not set.")

    @iv.setter
    def iv(self, value):
        self._iv = value


# Child Classes.
class AESCipher(BlockCipher):
    """AES symmetric cipher."""
    SUPPORTED_MODES = (
        AES.MODE_CBC,
        AES.MODE_CFB,
        AES.MODE_CTR,
        AES.MODE_ECB,
        AES.MODE_OFB,
        AES.MODE_OPENPGP,
        AES.MODE_PGP
    )

    def __init__(self, key=None, iv=None, mode=AES.MODE_CFB):
        super(AESCipher, self).__init__(key, iv)
        self.mode = mode

    @staticmethod
    def generate_iv():
        """Randomly create an IV."""
        return Random.new().read(AES.block_size)

    @property
    def mode(self):
        return self._mode

    @mode.setter
    def mode(self, value):
        if value not in AESCipher.SUPPORTED_MODES:
            raise ValueError("AES mode not supported.")

        self._mode = value


class XORCipher(CryptoCipher):
    """Implements Pycrypto bitwise XOR stream cipher.
    Vulnerable to frequency analysis. Appropriate for hiding data, not securing it.
    """
    def __init__(self, key=None):
        super(XORCipher, self).__init__(key)

    def encrypt(self, data):
        """Generate cipher, encrypt data and Base64 encode."""
        xor_cipher = XOR.new(self.key)
        return base64.b64encode(xor_cipher.encrypt(data))

    def decrypt(self, data):
        """Generate cipher, Base64 decode and decrypt data."""
        xor_cipher = XOR.new(self.key)
        return xor_cipher.decrypt(base64.b64decode(data))


class AESCipher(CryptoCipher):
    