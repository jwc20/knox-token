import binascii
import logging
from hmac import compare_digest

from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from ninja.security import HttpBearer, APIKeyHeader
from asgiref.sync import sync_to_async

from .crypto import hash_token
from .models import KnoxToken

AUTO_REFRESH = settings.AUTO_REFRESH
TOKEN_TTL = settings.TOKEN_TTL
MIN_REFRESH_INTERVAL_SECOND = settings.MIN_REFRESH_INTERVAL_SECOND
HTTP_HEADER_ENCODING = settings.HTTP_HEADER_ENCODING
AUTH_HEADER_PREFIX = settings.AUTH_HEADER_PREFIX
TOKEN_KEY_LENGTH = settings.TOKEN_KEY_LENGTH

logger = logging.getLogger(__name__)


def update_auth_token_expiry(auth_token_digest):
    new_expiry = timezone.now() + TOKEN_TTL
    KnoxToken.objects.filter(digest=auth_token_digest).update(expiry=new_expiry)


@sync_to_async
def update_auth_token_expiry_async(auth_token_digest):
    new_expiry = timezone.now() + TOKEN_TTL
    KnoxToken.objects.filter(digest=auth_token_digest).update(expiry=new_expiry)


class TokenAuthentication(HttpBearer):
    """
    This authentication scheme uses Knox AuthTokens for authentication.

    Similar to DRF's TokenAuthentication, it overrides a large amount of that
    authentication scheme to cope with the fact that Tokens are not stored
    in plaintext in the database

    If successful
    - `request.user` will be a django `User` instance
    - `request.auth` will be an `AuthToken` instance
    """

    param_name = AUTH_HEADER_PREFIX

    def authenticate(self, request, token, *args, **kwargs):
        return self._authenticate_credentials(token)

    async def authenticate_async(self, request, token, *args, **kwargs):
        return await self._authenticate_credentials_async(token)

    def _authenticate_credentials(self, token):
        """
        Due to the random nature of hashing a value, this must inspect
        each auth_token individually to find the correct one.

        Tokens that have expired will be deleted and skipped
        """
        for auth_token in KnoxToken.objects.filter(token_key=token[:TOKEN_KEY_LENGTH]):
            if self._cleanup_token(auth_token):
                continue
            try:
                digest = hash_token(token)
            except (TypeError, binascii.Error):
                raise Exception(
                    _(
                        "Invalid token header. Token string "
                        "should not contain invalid characters."
                    )
                )
            if compare_digest(digest, auth_token.digest):
                if AUTO_REFRESH and auth_token.expiry:
                    self._renew_token(auth_token)
                return self._validate_user(auth_token)
        raise Exception(_("Invalid token header."))

    async def _authenticate_credentials_async(self, token):
        """
        Async version of _authenticate_credentials.
        Due to the random nature of hashing a value, this must inspect
        each auth_token individually to find the correct one.

        Tokens that have expired will be deleted and skipped
        """
        auth_tokens = await sync_to_async(
            lambda: list(KnoxToken.objects.filter(token_key=token[:TOKEN_KEY_LENGTH]))
        )()

        for auth_token in auth_tokens:
            if await self._cleanup_token_async(auth_token):
                continue
            try:
                digest = hash_token(token)
            except (TypeError, binascii.Error):
                raise Exception(
                    _(
                        "Invalid token header. Token string "
                        "should not contain invalid characters."
                    )
                )
            if compare_digest(digest, auth_token.digest):
                if AUTO_REFRESH and auth_token.expiry:
                    await self._renew_token_async(auth_token)
                return await self._validate_user_async(auth_token)
        raise Exception(_("Invalid token header."))

    def _renew_token(self, auth_token):
        current_expiry = auth_token.expiry
        new_expiry = timezone.now() + TOKEN_TTL
        auth_token.expiry = new_expiry
        delta = (new_expiry - current_expiry).total_seconds()
        if delta > MIN_REFRESH_INTERVAL_SECOND:
            update_auth_token_expiry(auth_token.digest)

    async def _renew_token_async(self, auth_token):
        current_expiry = auth_token.expiry
        new_expiry = timezone.now() + TOKEN_TTL
        auth_token.expiry = new_expiry
        delta = (new_expiry - current_expiry).total_seconds()
        if delta > MIN_REFRESH_INTERVAL_SECOND:
            await update_auth_token_expiry_async(auth_token.digest)

    def _validate_user(self, auth_token):
        if not auth_token.user.is_active:
            raise Exception(_("User account is disabled."))
        return (auth_token.user, auth_token)

    async def _validate_user_async(self, auth_token):
        is_active = await sync_to_async(lambda: auth_token.user.is_active)()
        if not is_active:
            raise Exception(_("User account is disabled."))
        return (auth_token.user, auth_token)

    def _cleanup_token(self, auth_token):
        for user_auth_token in auth_token.user.knoxtoken_set.all():
            if user_auth_token.expiry < timezone.now():
                user_auth_token.delete()
        if auth_token.expiry is not None:
            if auth_token.expiry < timezone.now():
                auth_token.delete()
                return True
        return False

    async def _cleanup_token_async(self, auth_token):
        user_auth_tokens = await sync_to_async(
            lambda: list(auth_token.user.knoxtoken_set.all())
        )()

        for user_auth_token in user_auth_tokens:
            if user_auth_token.expiry < timezone.now():
                await sync_to_async(user_auth_token.delete)()

        if auth_token.expiry is not None:
            if auth_token.expiry < timezone.now():
                await sync_to_async(auth_token.delete)()
                return True
        return False


class AsyncTokenAuthentication(TokenAuthentication):
    """
    Async-first version of TokenAuthentication that uses async methods by default
    for use with async views in Django Ninja.
    """

    async def authenticate(self, request, token, *args, **kwargs):
        return await self._authenticate_credentials_async(token)


token_auth = TokenAuthentication()
async_token_auth = AsyncTokenAuthentication()
