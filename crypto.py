import binascii
from os import urandom as generate_bytes
# from .settings import knox_settings
# hash_func = knox_settings.SECURE_HASH_ALGORITHM

import binascii
from os import urandom as generate_bytes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import SHA512

SECURE_HASH_ALGORITHM = 'hashlib.sha512'
AUTH_TOKEN_CHARACTER_LENGTH = 64
hash_func = SECURE_HASH_ALGORITHM


# import hashlib
# class MockKnoxSettings:
#     AUTH_TOKEN_CHARACTER_LENGTH = 64  
#     SECURE_HASH_ALGORITHM = hashlib.sha256  
# knox_settings = MockKnoxSettings()
# hash_func = knox_settings.SECURE_HASH_ALGORITHM

def create_token_string() -> str:
    """
    Creates a secure random token string using hexadecimal encoding.

    The token length is determined by knox_settings.AUTH_TOKEN_CHARACTER_LENGTH.
    Since each byte is represented by 2 hexadecimal characters, the number of
    random bytes generated is half the desired character length.

    Returns:
        str: A hexadecimal string of length AUTH_TOKEN_CHARACTER_LENGTH containing
            random bytes.
    """
    return binascii.hexlify(
        generate_bytes(int(AUTH_TOKEN_CHARACTER_LENGTH / 2))
    ).decode()


def make_hex_compatible(token: str) -> bytes:
    """
    Converts a string token into a hex-compatible bytes object.

    We need to make sure that the token, that is send is hex-compatible.
    When a token prefix is used, we cannot guarantee that.

    Args:
        token (str): The token string to convert.

    Returns:
        bytes: The hex-compatible bytes representation of the token.
    """
    return binascii.unhexlify(binascii.hexlify(bytes(token, 'utf-8')))


def hash_token(token: str) -> str:
    """
    Calculates the hash of a token.

    Uses the hash algorithm specified in knox_settings.SECURE_HASH_ALGORITHM.
    The token is first converted to a hex-compatible format before hashing.

    Args:
        token (str): The token string to hash.

    Returns:
        str: The hexadecimal representation of the token's hash digest.

    Example:
        >>> hash_token("abc123")
        'a123f...'  # The actual hash will be longer
    """
    digest = hashes.Hash(
        SHA512(),
        backend=default_backend(),
    )
    digest.update(binascii.unhexlify(token))
    return binascii.hexlify(digest.finalize()).decode()

# if __name__ == '__main__':
#     print(hash_token('abc123'))
#     print(create_token_string())
