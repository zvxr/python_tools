
from Crypto import Random


class CryptoCipher(object):
    """Base Class for Ciphers."""
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
        raise AttributeError("Key is not set.")

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
        raise AttributeError("IV is not set.")

    @iv.setter
    def iv(self, value):
        self._iv = value

    def _get_pad_char(self, ignore=None):
        """Return a random character to pad data that does not match ignore."""
        random_device = Random.new()
        while True:
            char = random_device.read(1)
            if char != ignore:
                return char

    def pad_data(self, data, block_size):
        """Left pad data with a random character. Always add padding."""
        pad_char = self._get_pad_char(ignore=data[0])
        pad_size = (block_size - len(data)) % block_size or block_size
        return (pad_char * pad_size) + data

    def unpad_data(self, data):
        """Strip padding from data. It is expected that the `pad_data`
        method (or equivalent) has been applied.
        """
        return data.lstrip(data[0])