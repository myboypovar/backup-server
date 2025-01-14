from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA


AES_KEY_SIZE = 32  # (256 bits = 32 bytes)


class AESWrapper:
    """
    AES wrapper class that uses AES-CBC to encrypt and decrypt data.

    Attributes:
        aes_key (bytes): AES-CBC encrypted key
        iv (bytes): AES-CBC zeroed IV
    """
    def __init__(self):
        aes_key = get_random_bytes(AES_KEY_SIZE)  # Generate a random AES key
        self.aes_key = aes_key
        self.iv = b'\x00' * AES.block_size

    @staticmethod
    def import_rsa_public_key(binary_key: bytes) -> RSA.RsaKey:
        """
        Import RSA public key from a binary data
        :param binary_key: RSA public key in binary format
        :return: RSA public key object
        """
        try:
            rsa_key = RSA.importKey(binary_key)
            return rsa_key
        except ValueError:
            raise ValueError('RSA public key must be in binary format')

    def encrypt_aes_with_rsa(self, rsa_key_bytes: bytes) -> bytes:
        """
        Encrypt an AES key with RSA public key
        :param rsa_key_bytes: RSA public key in binary format:
        :return: encrypted AES key
        """
        rsa_key = AESWrapper.import_rsa_public_key(rsa_key_bytes)
        # Create an RSA cipher object
        rsa_cipher = PKCS1_OAEP.new(rsa_key)

        # Encrypt the AES key using the RSA public key
        encrypted_aes_key = rsa_cipher.encrypt(self.aes_key)
        return encrypted_aes_key

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plain text with AES-CBC symmetric encryption.
        :param plaintext: plain text to encrypt
        :return: ciphered text
        """
        # Use built-in padding function
        padded_plaintext = pad(plaintext, AES.block_size)
        # Create AES cipher with CBC mode and zeroed IV
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        # Encrypt the plaintext
        return cipher.encrypt(padded_plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext with AES-CBC symmetric encryption.
        :param ciphertext: ciphertext to decrypt
        :return: plaintext
        """
        # Create AES cipher with CBC mode
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        # Decrypt the ciphertext
        decrypted = cipher.decrypt(ciphertext)
        # Use built-in unpadding function
        return unpad(decrypted, AES.block_size)

    def get_aes_key(self) -> bytes:
        """ Get AES key """
        return self.aes_key
