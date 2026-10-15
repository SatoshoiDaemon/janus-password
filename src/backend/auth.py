import base64
import hmac
import os
import secrets
import string

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import VerificationError, InvalidHashError
from argon2.low_level import hash_secret_raw, Type

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PASSWORD_HASH_ITERATIONS = 100_000
ENCRYPTION_SALT_BYTES = 16
ENCRYPTED_VALUE_VERSION = "v1"


def legacy_hash_password(password):
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


def legacy_verify_password(password, password_hash):
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


def legacy_encrypt_password(value, key_password):
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


def legacy_decrypt_password(encrypted_value, key_password):
    """Decrypt a value created by :func:`encrypt_password`.

    Legacy ciphertexts using the old fixed salt are intentionally rejected;
    silently accepting them would preserve the insecure encryption scheme.
    """
    if not isinstance(encrypted_value, str) or not isinstance(key_password, str):
        return None
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


# Bounded, serialized-by-vault Argon2id operations keep local resource use predictable.
ARGON_MEMORY = 65536
ARGON_TIME = 3
ARGON_PARALLELISM = 1
password_hasher = PasswordHasher(
    time_cost=ARGON_TIME, memory_cost=ARGON_MEMORY, parallelism=ARGON_PARALLELISM, type=Type.ID
)


def hash_password(password):
    return password_hasher.hash(password)


def verify_password(password, password_hash):
    if not isinstance(password, str) or not isinstance(password_hash, str):
        return False
    if not password_hash.startswith("$argon2id$"):
        return legacy_verify_password(password, password_hash)
    try:
        params = extract_parameters(password_hash)
        if not (8192 <= params.memory_cost <= 262144 and 1 <= params.time_cost <= 10 and 1 <= params.parallelism <= 8):
            return False
        return password_hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError, ValueError):
        return False


def needs_rehash(value):
    if not value.startswith("$argon2id$"):
        return True
    return password_hasher.check_needs_rehash(value)


def encrypt_password(value, key_password, legacy=False):
    if legacy:
        return legacy_encrypt_password(value, key_password)
    if not isinstance(key_password, str) or not key_password:
        raise ValueError("An encryption password is required")
    salt = os.urandom(16)
    raw = hash_secret_raw(key_password.encode(), salt, ARGON_TIME, ARGON_MEMORY, ARGON_PARALLELISM, 32, Type.ID)
    token = Fernet(base64.urlsafe_b64encode(raw)).encrypt(value.encode()).decode()
    return (
        f"v3$argon2id${ARGON_MEMORY},{ARGON_TIME},{ARGON_PARALLELISM}${base64.urlsafe_b64encode(salt).decode()}${token}"
    )


def decrypt_password(encrypted_value, key_password):
    if not isinstance(encrypted_value, str) or not isinstance(key_password, str):
        return None
    if encrypted_value.startswith("v1$"):
        return legacy_decrypt_password(encrypted_value, key_password)
    try:
        version, algorithm, params, encoded_salt, token = encrypted_value.split("$", 4)
        memory, cost, parallelism = map(int, params.split(","))
        if (
            version != "v3"
            or algorithm != "argon2id"
            or not (8192 <= memory <= 262144 and 1 <= cost <= 10 and 1 <= parallelism <= 8)
        ):
            return None
        salt = base64.b64decode(encoded_salt, altchars=b"-_", validate=True)
        if len(salt) != 16:
            return None
        raw = hash_secret_raw(key_password.encode(), salt, cost, memory, parallelism, 32, Type.ID)
        return Fernet(base64.urlsafe_b64encode(raw)).decrypt(token.encode()).decode()
    except (ValueError, TypeError, InvalidToken, UnicodeError):
        return None


def generate_secure_password(length=16, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True):
    """Generate a cryptographically secure random password."""
    if length < 2 or length > 128:
        length = 16

    groups = []
    if use_lowercase:
        groups.append(string.ascii_lowercase)
    if use_uppercase:
        groups.append(string.ascii_uppercase)
    if use_digits:
        groups.append(string.digits)
    if use_special:
        groups.append("!@#$%^&*()_+-=[]{}|;:,.<>?")
    if not groups:
        groups = [string.ascii_letters, string.digits]
    if length < len(groups):
        raise ValueError("Aumente o comprimento para incluir todos os conjuntos selecionados")
    result = [secrets.choice(group) for group in groups]
    result.extend(secrets.choice("".join(groups)) for _ in range(length - len(groups)))
    secrets.SystemRandom().shuffle(result)
    return "".join(result)


def generate_access_token():
    """Generate an unguessable public-note access token."""
    return secrets.token_urlsafe(32)
