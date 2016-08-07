
import base64

from Crypto.Cipher import XOR




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
