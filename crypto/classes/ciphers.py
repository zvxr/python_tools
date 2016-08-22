
import base64

from collections import namedtuple
from Crypto import Random
from Crypto.Cipher import AES, XOR


# Base Classes.
class CryptoCipher(object):
    """Base Class for Ciphers."""
    EncryptedData = namedtuple('EncryptedData', ('data', 'pad_char'))

    def __init__(self, key=None):
        self._key = key
        self._encoder = None
        self._decoder = None

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
        """Apply encode method to data and return"""
        if hasattr(self._encoder, "__call__"):
            return self._encoder(data, *args, **kwargs)
        else:
            return data

    def _decode(self, data, *args, **kwargs):
        """Apply decode method to data and return."""
        if hasattr(self._decoder, "__call__"):
            return self._decoder(data, *args, **kwargs)
        else:
            return data

    def encrypt(self, data):
        raise NotImplemented("Method not defined.")

    def decrypt(self, data):
        raise NotImplemented("Method not defined.")

    def set_encoding(self, encoder, decoder):
        """Set encoder and decoder methods to be applied to data when encrypting
        and decrypting.
        """
        self._encoder = encoder
        self._decoder = decoder


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
        AES.MODE_OPENPGP
    )

    def __init__(self, key=None, iv=None, mode=AES.MODE_CFB):
        super(AESCipher, self).__init__(key, iv)
        self.mode = mode

    @staticmethod
    def generate_iv():
        """Randomly generate an IV byte string for various modes of AES."""
        return Random.new().read(AES.block_size)

    @staticmethod
    def generate_key(key_size=16):
        """Randomly generate a key of byte size `key_size`. Must be 16, 24, or 32."""
        if key_size not in (16, 24, 32):
            raise AttributeError(
                "key_size must be 16 (AES-128), 24 (AES-192), or 32 (AES-256)."
            )
        random_device = Random.new()
        return random_device.read(key_size)

    @property
    def key(self):
        if self._key is not None:
            return self._key
        raise Exception("Key is not set.")

    @key.setter
    def key(self, value):
        if value is not None and len(value) not in (16, 24, 32):
            raise AttributeError(
                "key must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes long."
            )
        self._key = value

    @property
    def mode(self):
        return self._mode

    @mode.setter
    def mode(self, value):
        if value not in AESCipher.SUPPORTED_MODES:
            raise ValueError("AES mode not supported.")

        self._mode = value

    def _get_pad_char(self, ignore=None):
        """Return a random character to pad data that does not match ignore."""
        random_device = Random.new()
        while True:
            char = random_device.read(1)
            if char != ignore:
                return char

    def encrypt(self, data):
        """Generate cipher, encrypt, and encode data."""
        pad_char = self._get_pad_char(data[0] if data else None)

        # Pad data.
        padded_data = data.rjust(((len(data) / 16) + 1) * 16, pad_char)

        # Instantiate cipher.
        # TODO: Should support counter for CTR and segment_size for CFB.
        #       This may warrent subclassing for each mode.
        if self.mode in (AES.MODE_ECB, AES.MODE_CTR):
            aes_cipher = AES.new(self.key, self.mode)
        else:
            aes_cipher = AES.new(self.key, self.mode, self.iv)

        encrypted_data = aes_cipher.encrypt(padded_data)
        return CryptoCipher(
            self._encode(encrypted_data),
            pad_char
        )

    def decrypt(self, data):
        """Generate cipher, decode, and decrypt data.
        Accepts CryptoCipher.EncryptedData instance or string.
        """
        if isinstance(data, 'CryptoCipher.EncryptedData'):
            encrypted_data = data.data
            pad_char = data.pad_char
        else:
            encrypted_data = data.data
            pad_char = None

        aes_cipher = AES.new(self.key, self.mode, self.iv)
        decoded_data = self._decode(data)
        return aes_cipher.decrypt(decoded_data).lstrip(pad_char)


class XORCipher(CryptoCipher):
    """Implements Pycrypto bitwise XOR stream cipher.
    Vulnerable to frequency analysis. Appropriate for hiding data, not securing it.
    """
    def __init__(self, key=None):
        super(XORCipher, self).__init__(key)

    def encrypt(self, data):
        """Generate cipher, encrypt and encode data."""
        xor_cipher = XOR.new(self.key)
        encrypted_data = xor_cipher.encrypt(data)
        return self._encode(encrypted_data)

    def decrypt(self, data):
        """Generate cipher, decode and decrypt data."""
        xor_cipher = XOR.new(self.key)
        encoded_data = self._decode(data)
        return xor_cipher.decrypt(encoded_data)
