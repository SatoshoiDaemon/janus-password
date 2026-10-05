import base64
import hmac
import os
import secrets
import string

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PASSWORD_HASH_ITERATIONS = 100_000
ENCRYPTION_SALT_BYTES = 16
ENCRYPTED_VALUE_VERSION = "v1"


def hash_password(password):
    """Hash a user or note password with a unique random salt."""
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PASSWORD_HASH_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.b64encode(salt + key).decode("ascii")


def verify_password(password, password_hash):
    """Verify a password without exposing cryptographic errors."""
    try:
        salt_and_key = base64.b64decode(password_hash, validate=True)
        salt = salt_and_key[:32]
        expected_key = salt_and_key[32:]
        if len(salt) != 32 or len(expected_key) != 32:
            return False

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PASSWORD_HASH_ITERATIONS,
        )
        actual_key = kdf.derive(password.encode("utf-8"))
        return hmac.compare_digest(actual_key, expected_key)
    except (ValueError, TypeError):
        return False


def _derive_cipher(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PASSWORD_HASH_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key)


def encrypt_password(value, key_password):
    """Encrypt a value with a per-item random salt.

    The stored format is ``v1$<base64 salt>$<Fernet token>``. The salt is
    public metadata and is required to derive the same key during decryption.
    """
    if not key_password:
        raise ValueError("An encryption password is required")

    salt = os.urandom(ENCRYPTION_SALT_BYTES)
    cipher = _derive_cipher(key_password, salt)
    token = cipher.encrypt(value.encode("utf-8")).decode("ascii")
    encoded_salt = base64.urlsafe_b64encode(salt).decode("ascii")
    return f"{ENCRYPTED_VALUE_VERSION}${encoded_salt}${token}"


def decrypt_password(encrypted_value, key_password):
    """Decrypt a value created by :func:`encrypt_password`.

    Legacy ciphertexts using the old fixed salt are intentionally rejected;
    silently accepting them would preserve the insecure encryption scheme.
    """
    try:
        version, encoded_salt, token = encrypted_value.split("$", 2)
        if version != ENCRYPTED_VALUE_VERSION:
            return None
        salt = base64.urlsafe_b64decode(encoded_salt.encode("ascii"))
        if len(salt) != ENCRYPTION_SALT_BYTES:
            return None
        cipher = _derive_cipher(key_password, salt)
        return cipher.decrypt(token.encode("ascii")).decode("utf-8")
    except (ValueError, TypeError, InvalidToken, UnicodeDecodeError):
        return None


def generate_secure_password(length=16, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True):
    """Generate a cryptographically secure random password."""
    if length < 2 or length > 128:
        length = 16

    characters = ""
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if not characters:
        characters = string.ascii_letters + string.digits

    return "".join(secrets.choice(characters) for _ in range(length))


def generate_access_token():
    """Generate an unguessable public-note access token."""
    return secrets.token_urlsafe(32)
