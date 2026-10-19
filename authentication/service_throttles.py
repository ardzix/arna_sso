"""Bound service credential exchange independently from human anonymous traffic."""
import hashlib

from rest_framework.throttling import SimpleRateThrottle


class ServiceTokenIPThrottle(SimpleRateThrottle):
    scope = 'service_token_ip'

    def get_cache_key(self, request, view):
        return self.cache_format % {'scope': self.scope, 'ident': self.get_ident(request)}


class ServiceTokenFailureThrottle(ServiceTokenIPThrottle):
    scope = 'service_token_failures'

    def get_cache_key(self, request, view):
        client = str(request.data.get('client_id', ''))
        if len(client) > 200:
            client = '<oversized>'
        ident = hashlib.sha256((self.get_ident(request) + '\0' + client).encode()).hexdigest()
        return self.cache_format % {'scope': self.scope, 'ident': ident}

    def throttle_success(self):
        # Merely checking the failure budget must not charge a successful exchange.
        return True

    def record_failure(self):
        return super().throttle_success()


class AuthenticatedServiceTokenThrottle(SimpleRateThrottle):
    scope = 'service_token_client'

    def get_cache_key(self, request, view):
        # Set only after active-account lookup and client-secret verification.
        return self.cache_format % {'scope': self.scope, 'ident': str(view.authenticated_service.id)}
