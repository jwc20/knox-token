from django.apps import apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model

from knox import crypto
from knox.settings import knox_settings


TOKEN_KEY_LENGTH = 15
DIGEST_LENGTH = 128

sha = knox_settings.SECURE_HASH_ALGORITHM

# User = settings.AUTH_USER_MODEL
User = get_user_model()


def get_expiry(expiry):
    if expiry is not None:
        expiry = timezone.now() + expiry
    return expiry


def get_digest_token():
    token = crypto.create_token_string()
    digest = crypto.hash_token(token)
    return digest, token


class KnoxTokenManager(models.Manager):
    def create(
        self,
        user,
        expiry=knox_settings.TOKEN_TTL,
        **kwargs,
    ):
        digest, token = get_digest_token()
        if expiry is not None:
            expiry = timezone.now() + expiry
        instance = super().create(
            token_key=token[: TOKEN_KEY_LENGTH],
            digest=digest,
            user=user,
            expiry=expiry,
            **kwargs,
        )
        return instance, token


class KnoxToken(models.Model):
    objects = KnoxTokenManager()

    digest = models.CharField(max_length=DIGEST_LENGTH, primary_key=True)
    token_key = models.CharField(
        max_length=TOKEN_KEY_LENGTH,
        db_index=True,
        help_text="Partial token value stored in DB, for reference only",
    )
    user = models.ForeignKey(
        User,
        null=False,
        blank=False,
        on_delete=models.CASCADE,
    )
    created = models.DateTimeField(auto_now_add=True)
    expiry = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.digest} : {self.user}"

