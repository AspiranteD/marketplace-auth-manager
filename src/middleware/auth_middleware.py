"""Request middleware that auto-injects authentication headers."""

from typing import Optional

import requests

from ..providers.base import AuthProvider


class AuthMiddleware:
    """Wraps an AuthProvider to transparently inject auth into every request.

    On a 401 response the middleware attempts a single token refresh
    and retries the request before propagating the failure.
    """

    def __init__(self, provider: AuthProvider, max_retries: int = 1):
        self._provider = provider
        self._max_retries = max_retries

    @property
    def provider(self) -> AuthProvider:
        return self._provider

    def prepare_request(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Inject the current auth header into a prepared request."""
        headers = self._provider.get_auth_header()
        if headers:
            request.headers.update(headers)
        return request

    def send(
        self,
        session: requests.Session,
        method: str,
        url: str,
        **kwargs,
    ) -> requests.Response:
        """Send an authenticated request with automatic retry on 401."""
        headers = kwargs.pop("headers", {}) or {}
        auth_headers = self._provider.get_auth_header()
        if auth_headers:
            headers.update(auth_headers)

        response = session.request(method, url, headers=headers, **kwargs)

        retries = 0
        while response.status_code == 401 and retries < self._max_retries:
            if not self._provider.refresh():
                break
            auth_headers = self._provider.get_auth_header()
            if auth_headers:
                headers.update(auth_headers)
            response = session.request(method, url, headers=headers, **kwargs)
            retries += 1

        return response

    def get(self, session: requests.Session, url: str, **kwargs) -> requests.Response:
        return self.send(session, "GET", url, **kwargs)

    def post(self, session: requests.Session, url: str, **kwargs) -> requests.Response:
        return self.send(session, "POST", url, **kwargs)
