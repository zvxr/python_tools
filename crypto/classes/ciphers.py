
import base64

from Crypto import Random
from Crypto.Cipher import AES, XOR


# Base Classes.
class CryptoCipher(object):
    """Base Class for Ciphers."""
    def __init__(self, key=None, encoder=None):
        self._key = key
        self.encoder = encoder

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

    def _encode(self, data, *args, **kwargs):
        """Apply encoder to data and return, if encoder is callable."""
        if hasattr(self.encoder, "__call__"):
            return self.encoder(data, *args, **kwargs)
        else:
            return data

    def encrypt(self, data):
        raise NotImplemented("Method not defined.")

    def decrypt(self, data):
        raise NotImplemented("Method not defined.")


class BlockCipher(CryptoCipher):
    """Base Class for Block Ciphers."""
    def __init__(self, key=None, iv=None, encoder=None):
        super(BlockCipher, self).__init__(key, encoder)
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

    def __init__(self, key=None, iv=None, mode=AES.MODE_CFB, encoder=None):
        super(AESCipher, self).__init__(key, iv, encoder)
        self.mode = mode

    @staticmethod
    def generate_iv(block_size=AES.block_size):
        """Randomly create an IV byte string, `block_size` bytes long."""
        return Random.new().read(block_size)

    @property
    def mode(self):
        return self._mode

    @mode.setter
    def mode(self, value):
        if value not in AESCipher.SUPPORTED_MODES:
            raise ValueError("AES mode not supported.")

        self._mode = value

    def _get_pad_char(self):
        """Return a random character to pad data."""
        #return Random.new().read(1)
        return "_"

    def encrypt(self, data):
        """Generate cipher, encrypt data and Base64 encode."""
        pad_char = Random.random()

        # Pad data.
        if self.mode == AES.MODE_OPENPGP:
            pass
        else:
            padded_data = data.ljust(16 - len(data) % 16, pad_char)

        # Instantiate cipher.
        if self.mode in (AES.MODE_ECB, AES.MODE_CTR):
            aes_cipher = AES.new(self.key, self.mode)
        elif self.mode == AES.MODE_OPENPGP:
            # IV must be block_size bytes long for encryption and block_size +2 bytes for decryption
            pass
        else:
            pass

        encrypted_data = aes_cipher.encrypt(padded_data)
        return self._encode(encrypted_data)


class XORCipher(CryptoCipher):
    """Implements Pycrypto bitwise XOR stream cipher.
    Vulnerable to frequency analysis. Appropriate for hiding data, not securing it.
    """
    def __init__(self, key=None, encoder=None):
        super(XORCipher, self).__init__(key, encoder)

    def encrypt(self, data):
        """Generate cipher, encrypt data and Base64 encode."""
        xor_cipher = XOR.new(self.key)
        encrypted_data = xor_cipher.encrypt(data)
        return self.encoder(encrypted_data)

    def decrypt(self, data):
        """Generate cipher, Base64 decode and decrypt data."""
        xor_cipher = XOR.new(self.key)
        encoded_data = encoder(data)
        return xor_cipher.decrypt(encoded_data)


class AESCipher(CryptoCipher):
    