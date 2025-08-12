"""
AES-256 encryption utilities for data-at-rest encryption
"""
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class DataEncryption:
    """
    Handles AES-256 encryption/decryption for sensitive data
    """
    
    def __init__(self):
        self._fernet = None
        self._initialize_encryption()
    
    def _initialize_encryption(self):
        """Initialize the encryption key and Fernet instance"""
        try:
            # Get encryption key from environment or generate one
            encryption_key = getattr(settings, 'DATA_ENCRYPTION_KEY', None)
            
            if not encryption_key:
                # Generate a key from a password (you should set this in production)
                password = getattr(settings, 'SECRET_KEY', 'default-password').encode()
                salt = b'weaponpowercloud_salt_2024'  # In production, use a random salt
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password))
                self._fernet = Fernet(key)
            else:
                self._fernet = Fernet(encryption_key.encode())
                
        except Exception as e:
            logger.error(f"Failed to initialize encryption: {e}")
            raise
    
    def encrypt(self, data):
        """
        Encrypt string data
        Args:
            data (str): Data to encrypt
        Returns:
            str: Base64 encoded encrypted data
        """
        if not data:
            return data
            
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            encrypted_data = self._fernet.encrypt(data)
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
        
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return data  # Return original data if encryption fails
    
    def decrypt(self, encrypted_data):
        """
        Decrypt string data
        Args:
            encrypted_data (str): Base64 encoded encrypted data
        Returns:
            str: Decrypted data
        """
        if not encrypted_data:
            return encrypted_data
            
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self._fernet.decrypt(encrypted_bytes)
            return decrypted_data.decode('utf-8')
        
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return encrypted_data  # Return original data if decryption fails
    
    def encrypt_binary(self, data):
        """
        Encrypt binary data (for images)
        Args:
            data (bytes): Binary data to encrypt
        Returns:
            bytes: Encrypted binary data
        """
        if not data:
            return data
            
        try:
            return self._fernet.encrypt(data)
        except Exception as e:
            logger.error(f"Binary encryption failed: {e}")
            return data
    
    def decrypt_binary(self, encrypted_data):
        """
        Decrypt binary data (for images)
        Args:
            encrypted_data (bytes): Encrypted binary data
        Returns:
            bytes: Decrypted binary data
        """
        if not encrypted_data:
            return encrypted_data
            
        try:
            return self._fernet.decrypt(encrypted_data)
        except Exception as e:
            logger.error(f"Binary decryption failed: {e}")
            return encrypted_data


# Global encryption instance
data_encryption = DataEncryption()
