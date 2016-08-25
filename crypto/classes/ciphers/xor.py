
from base import CryptoCipher
from Crypto.Cipher import XOR


class XORCipher(CryptoCipher):
    """Implements Pycrypto bitwise XOR stream cipher.
    Vulnerable to frequency analysis. Appropriate for hiding data, not securing it.
    """
    def __init__(self, key=None):
        super(XORCipher, self).__init__(key)

    def encrypt(self, data):
        """Generate cipher, encrypt, and encode data."""
        xor_cipher = XOR.new(self.key)
        encrypted_data = xor_cipher.encrypt(data)
        return self._encode(encrypted_data)

    def decrypt(self, data):
        """Generate cipher, decode, and decrypt data."""
        xor_cipher = XOR.new(self.key)
        encoded_data = self._decode(data)
        return xor_cipher.decrypt(encoded_data)
