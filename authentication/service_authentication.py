from dataclasses import dataclass
from uuid import UUID

from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken

from authentication.models import ServiceAccount


@dataclass(frozen=True)
class ServicePrincipal:
    id: UUID
    client_id: str
    organization_id: UUID | None
    scopes: frozenset[str]
    audience: str

    @property
    def pk(self):
        return self.id

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False


class ServiceTokenAuthentication(BaseAuthentication):
    keyword = b"Bearer"
    required_audience = "sso-iam"

    def authenticate(self, request):
        authorization = get_authorization_header(request).split()
        if not authorization:
            return None
        if len(authorization) != 2 or authorization[0] != self.keyword:
            raise AuthenticationFailed("Invalid service Authorization header.")

        try:
            token = AccessToken(authorization[1].decode("utf-8"))
            if token.get("principal_type") != "service":
                raise ValueError("not a service token")
            audience = token.get("aud")
            if audience != self.required_audience:
                raise ValueError("invalid audience")
            service_id = UUID(str(token["service_id"]))
            client_id = str(token["client_id"])
            organization_id = UUID(str(token["org_id"])) if token.get("org_id") else None
            scopes = frozenset(str(scope) for scope in token.get("scopes", []))
        except (KeyError, TokenError, TypeError, UnicodeDecodeError, ValueError) as exc:
            raise AuthenticationFailed("Invalid SSO IAM service token.") from exc

        service = ServiceAccount.objects.filter(
            id=service_id,
            client_id=client_id,
            organization_id=organization_id,
            is_active=True,
        ).first()
        if not service:
            raise AuthenticationFailed("Service account is inactive or no longer valid.")
        if self.required_audience not in (service.audiences or []):
            raise AuthenticationFailed("Service account is not allowed to access SSO IAM.")

        return ServicePrincipal(
            id=service_id,
            client_id=client_id,
            organization_id=organization_id,
            scopes=scopes,
            audience=self.required_audience,
        ), token

    def authenticate_header(self, request):
        del request
        return "Bearer"
