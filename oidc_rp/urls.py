"""
    OpenID Connect relying party (RP) URLs
    ======================================

    This modules defines the URLs allowing to perform OpenID Connect flows on a Relying Party (RP).
    It defines three main endpoints: the authentication request endpoint, the authentication
    callback endpoint and the end session endpoint.

"""

from django.conf.urls import url

from . import views


urlpatterns = [
    url(r'^auth/request/$', views.OIDCAuthRequestView.as_view(), name='oidc_auth_request'),
    url(r'^auth/cb/$', views.OIDCAuthCallbackView.as_view(), name='oidc_auth_callback'),
    url(r'^end-session/$', views.OIDCEndSessionView.as_view(), name='oidc_end_session'),
    url(r'^refresh-token/$', views.OIDCRefreshTokenRF.as_view(), name='oidc_refresh_token'),
    url(r'^token/$', views.OIDCAuthority.as_view(), name='oidc_token'),
]
