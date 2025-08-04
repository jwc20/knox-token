import datetime
from typing import Tuple

from django.contrib.auth import get_user_model

from knoxtokens.models import KnoxToken

# from utils.exceptions import KnoxTokenDeleteFailed

User = get_user_model()


class CreateToken:
    def __init__(self, user: User):
        self.user = user

    def create(self) -> Tuple[str, datetime.datetime]:
        knox_token, token_value = KnoxToken.objects.create(user=self.user)
        return token_value, knox_token.expiry


class DeleteToken:
    def __init__(self, user: User, knox_token: KnoxToken | None = None):
        self.user = user
        self.knox_token = knox_token

    def delete(self):
        # TODO: auth_token should be the knox_token
        deleted_info = self.user.authtoken_set.filter(
            digest=self.auth_token.digest
        ).delete()
        if deleted_info[0] != 1:
            raise KnoxTokenDeleteFailed()

    def delete_all(self):
        self.user.authtoken_set.all().delete()
