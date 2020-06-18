# This file is part of Flask-Multipass-CERN.
# Copyright (C) 2020 CERN
#
# Flask-Multipass-CERN is free software; you can redistribute
# it and/or modify it under the terms of the MIT License; see
# the LICENSE file for more details.

from __future__ import print_function, unicode_literals

from functools import wraps
from inspect import getcallargs

from authlib.integrations.requests_client import OAuth2Session
from flask import current_app, g, has_request_context
from flask_multipass.data import IdentityInfo
from flask_multipass.exceptions import IdentityRetrievalFailed, MultipassException
from flask_multipass.group import Group
from flask_multipass.identity import IdentityProvider
from flask_multipass.providers.authlib import AuthlibAuthProvider, _authlib_oauth


CERN_OIDC_WELLKNOWN_URL = 'https://auth.cern.ch/auth/realms/cern/.well-known/openid-configuration'


# TODO check if the DB still contains crap:
# - affiliations starting with `eduGAIN - `
# - affiliations starting with `urn:`
# - first name containing `https://me.yahoo.com`


def memoize_request(f):
    @wraps(f)
    def memoizer(*args, **kwargs):
        if not has_request_context() or current_app.config['TESTING'] or current_app.config.get('REPL'):
            # No memoization outside request context
            return f(*args, **kwargs)

        try:
            cache = g._cern_multipass_memoize
        except AttributeError:
            g._cern_multipass_memoize = cache = {}

        key = (f.__module__, f.__name__, make_hashable(getcallargs(f, *args, **kwargs)))
        if key not in cache:
            cache[key] = f(*args, **kwargs)
        return cache[key]

    return memoizer


def make_hashable(obj):
    if isinstance(obj, (list, set)):
        return tuple(obj)
    elif isinstance(obj, dict):
        return frozenset((k, make_hashable(v)) for k, v in obj.items())
    return obj


class CERNAuthProvider(AuthlibAuthProvider):
    def __init__(self, *args, **kwargs):
        super(CERNAuthProvider, self).__init__(*args, **kwargs)
        self.include_token = 'only'  # we get all data from the identity API

    @property
    def authlib_settings(self):
        settings = dict(self.settings['authlib_args'])
        settings.setdefault('server_metadata_url', CERN_OIDC_WELLKNOWN_URL)
        # XXX should we request any other scopes?
        settings.setdefault('client_kwargs', {'scope': 'openid'})
        return settings


class CERNGroup(Group):
    supports_member_list = True

    def _get_group_id(self, api_session):
        data = self.provider._get_group_data(self.name)
        if not data:
            return None
        return data['id']

    def get_members(self):
        with self.provider._get_api_session() as api_session:
            gid = self._get_group_id(api_session)
            if not gid:
                return
            params = {
                'limit': 5000,
                'field': [
                    'upn',
                    'firstName',
                    'lastName',
                    'instituteName',
                    'primaryAccountEmail',
                ],
                'recursive': 'true'
            }
            results = self.provider._fetch_all(api_session, '/api/v1.0/Group/{}/memberidentities'.format(gid), params)
        for res in results:
            del res['id']  # id is always included
            yield IdentityInfo(self.provider, res.pop('upn'), **res)

    def has_member(self, identifier):
        with self.provider._get_api_session() as api_session:
            gid = self._get_group_id(api_session)
            if not gid:
                return False
            params = {
                'filter': ['upn:eq:{}'.format(identifier)],
                'field': ['upn'],
                'recursive': 'true'
            }
            results = self.provider._fetch_all(api_session, '/api/v1.0/Group/{}/memberidentities'.format(gid), params)
            return len(results) == 1 and results[0]['upn'] == identifier


class CERNIdentityProvider(IdentityProvider):
    supports_refresh = False
    supports_get = False
    supports_search = True
    supports_groups = True
    supports_get_identity_groups = True
    group_class = CERNGroup

    def __init__(self, *args, **kwargs):
        super(CERNIdentityProvider, self).__init__(*args, **kwargs)
        self.authlib_client = _authlib_oauth.register(self.name + '-idp', **self.authlib_settings)
        self.settings.setdefault('authz_api', 'https://authorization-service-api.web.cern.ch')
        self.settings['mapping'] = {
            'first_name': 'firstName',
            'last_name': 'lastName',
            'affiliation': 'instituteName',
            'email': 'primaryAccountEmail',
        }

    @property
    def authlib_settings(self):
        settings = dict(self.settings['authlib_args'])
        settings.setdefault('server_metadata_url', CERN_OIDC_WELLKNOWN_URL)
        return settings

    @property
    def authz_api_base(self):
        return self.settings['authz_api'].rstrip('/')

    def get_identity_from_auth(self, auth_info):
        data = self._fetch_identity_data(auth_info)
        return IdentityInfo(self, data.pop('upn'), **data)

    @memoize_request
    def search_identities(self, criteria, exact=False):
        if any(len(x) != 1 for x in criteria.values()):
            # Unfortunately the API does not support OR filters (yet?).
            # Fortunately we never search for more than one value anyway!
            raise MultipassException('This provider does not support multiple values for a search criterion',
                                     provider=self)

        criteria = {k: next(iter(v)) for k, v in criteria.items()}
        op = 'eq' if exact else 'contains'
        api_criteria = ['{}:{}:{}'.format(k, op, v) for k, v in criteria.items()]
        api_criteria.append('type:eq:Person')
        params = {
            'limit': 5000,
            'filter': api_criteria,
            'field': [
                'upn',
                'firstName',
                'lastName',
                'instituteName',
                'primaryAccountEmail',
            ],
        }

        with self._get_api_session() as api_session:
            results = self._fetch_all(api_session, '/api/v1.0/Identity', params)

        for res in results:
            del res['id']
            yield IdentityInfo(self, res['upn'], **res)

    def get_identity_groups(self, identifier):
        with self._get_api_session() as api_session:
            iid = self._get_identity_id_by_upn(api_session, identifier)
            results = self._fetch_all(api_session, '/api/v1.0/Identity/{}/groups'.format(iid), {'recursive': 'true'})
        return {self.group_class(self, res['groupIdentifier']) for res in results}

    def get_group(self, name):
        group_data = self._get_group_data(name)
        if not group_data:
            return None
        return self.group_class(self, group_data['groupIdentifier'])

    def search_groups(self, name, exact=False):
        params = {
            'limit': 5000,
            'filter': ['groupIdentifier:{}:{}'.format('eq' if exact else 'contains', name)],
            'field': ['groupIdentifier'],
        }
        with self._get_api_session() as api_session:
            results = self._fetch_all(api_session, '/api/v1.0/Group', params)
        return {self.group_class(self, res['groupIdentifier']) for res in results}

    @memoize_request
    def _get_api_session(self):
        meta = self.authlib_client.load_server_metadata()
        token_endpoint = meta['token_endpoint'].replace('protocol/openid-connect', 'api-access')
        oauth_session = OAuth2Session(
            self.authlib_client.client_id,
            self.authlib_client.client_secret,
            token_endpoint=token_endpoint,
            grant_type='client_credentials',
        )
        oauth_session.fetch_access_token(
            audience='authorization-service-api',
            headers={'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'},
        )
        return oauth_session

    def _fetch_identity_data(self, auth_info):
        # Exchange the user token to one for the authorization API
        user_api_token = self.authlib_client.fetch_access_token(
            grant_type='urn:ietf:params:oauth:grant-type:token-exchange',
            subject_token_type='urn:ietf:params:oauth:token-type:access_token',
            audience='authorization-service-api',
            subject_token=auth_info.data['token']['access_token'],
        )

        params = {
            'field': [
                'upn',
                'firstName',
                'lastName',
                'instituteName',
                'primaryAccountEmail',
            ],
        }
        resp = self.authlib_client.get(self.authz_api_base + '/api/v1.0/Identity/current', token=user_api_token,
                                       params=params)
        resp.raise_for_status()
        data = resp.json()['data']
        del data['id']  # id is always included
        return data

    def _fetch_all(self, api_session, endpoint, params):
        results = []
        resp = api_session.get(self.authz_api_base + endpoint, params=params)
        resp.raise_for_status()
        data = resp.json()

        while True:
            results += data['data']
            if not data['pagination']['next']:
                break
            resp = api_session.get(self.authz_api_base + data['pagination']['next'])
            resp.raise_for_status()
            data = resp.json()
        return results

    def _get_identity_id_by_upn(self, api_session, upn):
        params = {
            'filter': 'upn:eq:{}'.format(upn),
            'field': ['id']
        }
        resp = api_session.get(self.authz_api_base + '/api/v1.0/Identity', params=params)
        resp.raise_for_status()
        data = resp.json()
        if len(data['data']) != 1:
            raise IdentityRetrievalFailed('Could not get identity id', provider=self)
        return data['data'][0]['id']

    @memoize_request
    def _get_group_data(self, name):
        params = {
            'filter': ['groupIdentifier:eq:{}'.format(name)],
            'field': ['id', 'groupIdentifier'],
        }
        with self._get_api_session() as api_session:
            resp = api_session.get(self.authz_api_base + '/api/v1.0/Group', params=params)
            resp.raise_for_status()
            data = resp.json()
        if len(data['data']) != 1:
            return None
        return data['data'][0]
