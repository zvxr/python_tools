
from base import BlockCipher
from Crypto import Random
from Crypto.Cipher import AES


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
        self._mode = mode

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
        raise AttributeError("Key is not set.")

    @key.setter
    def key(self, value):
        if value is not None and len(value) not in (16, 24, 32):
            raise AttributeError(
                "key must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes long."
            )
        self._key = value

    @property
    def mode(self):
        if self._mode is not None:
            return self._mode
        raise AttributeError("Mode is not set.")

    @mode.setter
    def mode(self, value):
        if value not in AESCipher.SUPPORTED_MODES:
            raise AttributeError("AES mode not supported.")
        self._mode = value

    def _get_cipher(self):
        """Return a Pycrypto AES cipher instance.
        `key`, `mode` and depending on mode `iv` must be set.
        """
        if self.mode in (AES.MODE_ECB, AES.MODE_CTR):
            return AES.new(self.key, self.mode)
        return AES.new(self.key, self.mode, self.iv)

    def encrypt(self, data):
        """Generate cipher, encrypt, and encode data."""
        aes_cipher = self._get_cipher()
        padded_data = self.pad_data(data, AES.block_size)
        encrypted_data = aes_cipher.encrypt(padded_data)
        return self._encode(encrypted_data)

    def decrypt(self, data):
        """Generate cipher, decode, and decrypt data."""
        aes_cipher = self._get_cipher()
        decoded_data = self._decode(data)
        decrypted_data = aes_cipher.decrypt(decoded_data)
        return self.unpad_data(decrypted_data)
