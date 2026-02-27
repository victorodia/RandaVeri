import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import base64
import json
from dotenv import load_dotenv

load_dotenv()

class CryptoService:
    def __init__(self, key_str: str = None, iv_str: str = None):
        # Load from env if not provided (fallback to old keys for safety if not in env yet)
        self._raw_key = key_str or os.getenv("CRYPTO_KEY", "FD!-F=15B46BAD21")
        self.key = self._prepare_key(self._raw_key)
        # Standard IV for legacy decryption compatibility
        self.legacy_iv = (iv_str or os.getenv("CRYPTO_IV", "0123456789012345")).encode('utf-8')

    def _prepare_key(self, key_str: str) -> bytes:
        key = key_str.encode('utf-8')
        if len(key) < 32:
            key = key.ljust(32, b'\0')
        elif len(key) > 32:
            key = key[:32]
        return key

    def encrypt(self, data: dict) -> str:
        """
        Encrypts data using AES-CBC with a random IV.
        The IV is prepended to the ciphertext.
        """
        json_str = json.dumps(data)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = pad(json_str.encode('utf-8'), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        # Combine IV + Ciphertext for storage/transmission
        return base64.b64encode(iv + encrypted_data).decode('utf-8')

    def decrypt(self, encrypted_b64: str) -> dict:
        """
        Decrypts data using AES-CBC. Handles both random IV (new) 
        and legacy static IV (old) formats.
        """
        raw_data = base64.b64decode(encrypted_b64)
        
        # Check if payload contains a prepended IV (length should be at least block_size + 1 block)
        if len(raw_data) >= AES.block_size + AES.block_size:
            try:
                iv = raw_data[:AES.block_size]
                ciphertext = raw_data[AES.block_size:]
                cipher = AES.new(self.key, AES.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
                return json.loads(decrypted_data.decode('utf-8'))
            except Exception:
                # If decryption with prepended IV fails, try legacy static IV
                pass
        
        # Legacy decryption fallback
        cipher = AES.new(self.key, AES.MODE_CBC, self.legacy_iv)
        decrypted_data = unpad(cipher.decrypt(raw_data), AES.block_size)
        return json.loads(decrypted_data.decode('utf-8'))

# Initialize with environment defaults
crypto_service = CryptoService()
