"""
    OpenID Connect relying party (RP) model admin definitions
    =========================================================

    This module defines admin classes used to populate the Django administration dashboard.

"""

from django.contrib import admin

from .models import OIDCUser, OIDCPolling_Detail


@admin.register(OIDCUser)
class UserAdmin(admin.ModelAdmin):
    """ The OIDC user model admin. """

    list_display = ('sub', 'user', )

@admin.register(OIDCPolling_Detail)
class PollingDetail(admin.ModelAdmin):
    """ The OIDC user model admin. """

    list_display = ('polling_id', 'status', )
