import binascii
import logging
from hmac import compare_digest

from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from ninja.security import HttpBearer
from ninja.errors import HttpError, AuthenticationError

from .crypto import hash_token
from .models import KnoxToken

# from .settings import CONSTANTS 

AUTO_REFRESH = False
TOKEN_TTL = timezone.timedelta(days=90)
MIN_REFRESH_INTERVAL_SECOND = 60 * 60 * 24,
HTTP_HEADER_ENCODING = 'iso-8859-1'
AUTH_HEADER_PREFIX = "TOKEN"

logger = logging.getLogger(__name__)


def update_auth_token_expiry(auth_token_digest):
    new_expiry = timezone.now() + TOKEN_TTL
    KnoxToken.objects.filter(digest=auth_token_digest).update(expiry=new_expiry)


class TokenAuthentication(HttpBearer):
    '''
    This authentication scheme uses Knox AuthTokens for authentication.

    Similar to DRF's TokenAuthentication, it overrides a large amount of that
    authentication scheme to cope with the fact that Tokens are not stored
    in plaintext in the database

    If successful
    - `request.user` will be a django `User` instance
    - `request.auth` will be an `AuthToken` instance
    '''
    def authenticate(self, request):
        auth = request.META.get(
            f"HTTP_{AUTH_HEADER_PREFIX.upper()}", None
        )
        if not auth:
            raise Exception(_('Invalid token header.'))
        return self._authenticate_credentials(auth)
    

    def _authenticate_credentials(self, token):
        """
        Due to the random nature of hashing a value, this must inspect
        each auth_token individually to find the correct one.

        Tokens that have expired will be deleted and skipped
        """
        for auth_token in KnoxToken.objects.filter(token_key=token[:8]):
            if self._cleanup_token(auth_token):
                continue
            try:
                digest = hash_token(token)
            except (TypeError, binascii.Error):
                raise Exception(_('Invalid token header. Token string '
                                  'should not contain invalid characters.'))
            if compare_digest(digest, auth_token.digest):
                if AUTO_REFRESH and auth_token.expiry:
                    self._renew_token(auth_token)
                return self._validate_user(auth_token)
        raise Exception(_('Invalid token header.'))

    def _renew_token(self, auth_token):
        current_expiry = auth_token.expiry
        new_expiry = timezone.now() + TOKEN_TTL
        auth_token.expiry = new_expiry
        delta = (new_expiry - current_expiry).total_seconds()
        if delta > MIN_REFRESH_INTERVAL_SECOND:
            update_auth_token_expiry(auth_token.digest)

    def _validate_user(self, auth_token):
        if not auth_token.user.is_active:
            raise Exception(_('User account is disabled.'))
        return (auth_token.user, auth_token)

    def _cleanup_token(self, auth_token):
        for user_auth_token in auth_token.user.authtoken_set.all():
            if user_auth_token.expiry < timezone.now():
                user_auth_token.delete()
        if auth_token.expiry is not None:
            if auth_token.expiry < timezone.now():
                auth_token.delete()
                return True
        return False


token_auth = TokenAuthentication()

