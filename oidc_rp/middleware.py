"""
    OpenID Connect relying party (RP) middlewares
    =============================================

    This modules defines middlewares allowing to better handle users authenticated using an OpenID
    Connect provider (OP). One of the main middlewares is responsible for periodically refreshing
    ID tokens and access tokens.

"""

import time

import requests
import requests.exceptions
from django.contrib import auth
from django.core.exceptions import PermissionDenied

from .conf import settings as oidc_rp_settings
from .utils import validate_and_return_id_token
from .models import UserToken,OIDCUser


class OIDCRefreshIDTokenMiddleware:
    """ Allows to periodically refresh the ID token associated with the authenticated user. """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Refreshes tokens only in the applicable cases.
        if request.method == 'GET' and not request.is_ajax() and request.user.is_authenticated:
            self.refresh_token(request)
        response = self.get_response(request)
        return response

    def refresh_token(self, request):
        """ Refreshes the token of the current user. """
        # NOTE: no refresh token in the session means that the user wasn't authentified using the
        # OpenID Connect provider (OP).
        refresh_token = request.session.get('oidc_auth_refresh_token')
        if refresh_token is None:
            return

        id_token_exp_timestamp = request.session.get('oidc_auth_id_token_exp_timestamp', None)
        now_timestamp = time.time()
        # Returns immediatelly if the token is still valid.
        if id_token_exp_timestamp is not None and id_token_exp_timestamp > now_timestamp:
            return

        # Prepares the token payload that will be used to request a new token from the token
        # endpoint.
        refresh_token = request.session.pop('oidc_auth_refresh_token')
        token_payload = {
            'client_id': oidc_rp_settings.CLIENT_ID,
            'client_secret': oidc_rp_settings.CLIENT_SECRET,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }

        # Calls the token endpoint.
        token_response = requests.post(oidc_rp_settings.PROVIDER_TOKEN_ENDPOINT, data=token_payload)
        try:
            token_response.raise_for_status()
        except requests.exceptions.HTTPError:
            auth.logout(request)
            return
        token_response_data = token_response.json()

        # Validates the token.
        raw_id_token = token_response_data.get('id_token')
        id_token = validate_and_return_id_token(raw_id_token, validate_nonce=False)

        # If the token cannot be validated we have to log out the current user.
        if id_token is None:
            auth.logout(request)
            return

        # Retrieves the access token and refresh token.
        access_token = token_response_data.get('access_token')
        refresh_token = token_response_data.get('refresh_token')

        # Stores the ID token, the related access token and the refresh token in the session.
        request.session['oidc_auth_id_token'] = raw_id_token
        request.session['oidc_auth_access_token'] = access_token
        request.session['oidc_auth_refresh_token'] = refresh_token

        # Saves the new expiration timestamp.
        request.session['oidc_auth_id_token_exp_timestamp'] = \
            time.time() + oidc_rp_settings.ID_TOKEN_MAX_AGE

class OIDCRefreshIDTokenMiddlewareRF:
    """ Allows to periodically refresh the ID token associated with the authenticated user. """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Refreshes tokens only in the applicable cases.
        header = None
        user_token = None
        if request.META.get('HTTP_AUTHORIZATION'):
            header = request.META.get('HTTP_AUTHORIZATION', b'').split(" ")
        
        if header:
            try:
                user_token = UserToken.objects.get(access_token=header[1])
            except:
                raise PermissionDenied()

        if request.method == 'GET' and request.path == '/oidc/refresh-token/' and user_token:
            self.refresh_token(request)
        response = self.get_response(request)
        return response

    def refresh_token(self, request):
        """ Refreshes the token of the current user. """
        # NOTE: no refresh token in the session means that the user wasn't authentified using the
        header = request.META.get('HTTP_AUTHORIZATION', b'').split(" ")
        user_token = UserToken.objects.get(access_token=header[1])
        refresh_token = user_token.refresh_token
        request.session['oidc_auth_access_token'] = user_token.access_token
        if refresh_token is None:
            return

        id_token_exp_timestamp = float(user_token.exp_time)
        now_timestamp = time.time()
        # Returns immediatelly if the token is still valid.
        # if id_token_exp_timestamp is not None and id_token_exp_timestamp > now_timestamp:
        #     return

        # Prepares the token payload that will be used to request a new token from the token
        # endpoint.
        
        token_payload = {
            'client_id': oidc_rp_settings.CLIENT_ID,
            'client_secret': oidc_rp_settings.CLIENT_SECRET,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }

        # Calls the token endpoint.
        token_response = requests.post(oidc_rp_settings.PROVIDER_TOKEN_ENDPOINT, data=token_payload)
        try:
            token_response.raise_for_status()
        except requests.exceptions.HTTPError:
            auth.logout(request)
            return
        token_response_data = token_response.json()

        # Validates the token.
        raw_id_token = token_response_data.get('id_token')
        id_token = validate_and_return_id_token(raw_id_token, validate_nonce=False)

        # If the token cannot be validated we have to log out the current user.
        if id_token is None:
            auth.logout(request)
            return

        # Retrieves the access token and refresh token.
        access_token = token_response_data.get('access_token')
        refresh_token = token_response_data.get('refresh_token')

        # Stores the ID token, the related access token and the refresh token in the session.
        UserToken.objects.update_or_create(
            oidc_user = user_token.oidc_user,
            defaults={
                'access_token':access_token,
                'refresh_token':refresh_token,
                'id_token':raw_id_token,
                'exp_time':time.time() + oidc_rp_settings.ID_TOKEN_MAX_AGE,
                },
        )
        request.session['oidc_auth_access_token'] = access_token
