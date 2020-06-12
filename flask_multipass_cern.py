# This file is part of Flask-Multipass-CERN.
# Copyright (C) 2020 CERN
#
# Flask-Multipass-CERN is free software; you can redistribute
# it and/or modify it under the terms of the MIT License; see
# the LICENSE file for more details.

from __future__ import unicode_literals

from flask_multipass.providers.authlib import AuthlibAuthProvider, AuthlibIdentityProvider

CERN_OIDC_WELLKNOWN = 'https://auth.cern.ch/auth/realms/cern/.well-known/openid-configuration'


# TODO check if the DB still contains crap:
# - affiliations starting with `eduGAIN - `
# - affiliations starting with `urn:`
# - first name containing `https://me.yahoo.com`


class CERNAuthProvider(AuthlibAuthProvider):
    def __init__(self, *args, **kwargs):
        super(CERNAuthProvider, self).__init__(*args, **kwargs)
        self.use_id_token = False
        self.include_token = True

    @property
    def authlib_settings(self):
        settings = dict(self.settings['authlib_args'])
        settings.setdefault('server_metadata_url', CERN_OIDC_WELLKNOWN)
        # XXX should we request any other scopes?
        settings.setdefault('client_kwargs', {'scope': 'openid'})
        return settings


class CERNIdentityProvider(AuthlibIdentityProvider):
    def __init__(self, *args, **kwargs):
        super(CERNIdentityProvider, self).__init__(*args, **kwargs)
        self.settings['mapping'] = {
            'first_name': 'given_name',
            'last_name': 'family_name',
        }
