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
from flask_multipass.exceptions import MultipassException
from flask_multipass.group import Group
from flask_multipass.identity import IdentityProvider
from flask_multipass.providers.authlib import AuthlibAuthProvider, _authlib_oauth


CERN_OIDC_WELLKNOWN_URL = 'https://auth.cern.ch/auth/realms/cern/.well-known/openid-configuration'


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

    def __init__(self, provider, name, id):
        self.id = id
        super(CERNGroup, self).__init__(provider, name)

    def get_members(self):
        with self.provider._get_api_session() as api_session:
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
            results = self.provider._fetch_all(api_session, '/api/v1.0/Group/{}/memberidentities'.format(self.id),
                                               params)[0]
        for res in results:
            del res['id']  # id is always included
            yield IdentityInfo(self.provider, res.pop('upn'), **res)

    def has_member(self, identifier):
        with self.provider._get_api_session() as api_session:
            path = '/api/v1.0/Identity/{}/isMemberRecursive/{}'.format(identifier, self.name)
            resp = api_session.get(self.provider.authz_api_base + path)
            if resp.status_code == 404:
                return False
            resp.raise_for_status()
            data = resp.json()
        return data['data']['isMember']


class CERNIdentityProvider(IdentityProvider):
    supports_refresh = False
    supports_get = False
    supports_search = True
    supports_search_ex = True
    supports_groups = True
    supports_get_identity_groups = True
    group_class = CERNGroup

    def __init__(self, *args, **kwargs):
        super(CERNIdentityProvider, self).__init__(*args, **kwargs)
        self.authlib_client = _authlib_oauth.register(self.name + '-idp', **self.authlib_settings)
        self.settings.setdefault('extra_search_filters', [])
        self.settings.setdefault('authz_api', 'https://authorization-service-api.web.cern.ch')
        self.settings.setdefault('mapping', {
            'first_name': 'firstName',
            'last_name': 'lastName',
            'affiliation': 'instituteName',
            'email': 'primaryAccountEmail',
        })

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

    def search_identities(self, criteria, exact=False):
        return iter(self.search_identities_ex(criteria, exact=exact)[0])

    @memoize_request
    def search_identities_ex(self, criteria, exact=False, limit=None):
        if any(len(x) != 1 for x in criteria.values()):
            # Unfortunately the API does not support OR filters (yet?).
            # Fortunately we never search for more than one value anyway, except for emails when
            # looking up identities based on the user's email address.
            if len(criteria) != 1:
                raise MultipassException('This provider does not support multiple values for a search criterion',
                                         provider=self)

            field, values = dict(criteria).popitem()
            seen = set()
            total = 0
            all_identities = []
            for value in values:
                identities = self.search_identities_ex({field: [value]}, exact=exact, limit=limit)[0]
                for identity in identities:
                    if identity.identifier not in seen:
                        seen.add(identity.identifier)
                        all_identities.append(identity)
                        total += 1
            return all_identities, total

        criteria = {k: next(iter(v)) for k, v in criteria.items()}
        op = 'eq' if exact else 'contains'
        api_criteria = ['{}:{}:{}'.format(k, op, v) for k, v in criteria.items()]
        api_criteria.append('type:eq:Person')
        api_criteria += self.settings['extra_search_filters']
        params = {
            'limit': limit or 5000,
            'filter': api_criteria,
            'field': [
                'upn',
                'firstName',
                'lastName',
                'displayName',
                'instituteName',
                'primaryAccountEmail',
            ],
        }

        with self._get_api_session() as api_session:
            results, total = self._fetch_all(api_session, '/api/v1.0/Identity', params, limit=limit)

        identities = []
        for res in results:
            del res['id']
            identities.append(IdentityInfo(self, res['upn'], **res))
        return identities, total

    def get_identity_groups(self, identifier):
        with self._get_api_session() as api_session:
            path = self.authz_api_base + '/api/v1.0/IdentityMembership/{}/precomputed'
            resp = api_session.get(path.format(identifier))
            resp.raise_for_status()
            results = resp.json()['data']
        return {self.group_class(self, res['groupIdentifier'], res['groupId']) for res in results}

    def get_group(self, name):
        group_data = self._get_group_data(name)
        if not group_data:
            return None
        return self.group_class(self, group_data['groupIdentifier'], group_data['id'])

    def search_groups(self, name, exact=False):
        params = {
            'limit': 5000,
            'filter': ['groupIdentifier:{}:{}'.format('eq' if exact else 'contains', name)],
            'field': ['groupIdentifier', 'id'],
        }
        with self._get_api_session() as api_session:
            results = self._fetch_all(api_session, '/api/v1.0/Group', params)[0]
        return {self.group_class(self, res['groupIdentifier'], res['id']) for res in results}

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

    def _fetch_all(self, api_session, endpoint, params, limit=None):
        results = []
        resp = api_session.get(self.authz_api_base + endpoint, params=params)
        resp.raise_for_status()
        data = resp.json()
        total = data['pagination']['total']

        while True:
            results += data['data']
            if not data['pagination']['next'] or (limit is not None and len(results) >= limit):
                break
            resp = api_session.get(self.authz_api_base + data['pagination']['next'])
            resp.raise_for_status()
            data = resp.json()
        if limit is not None:
            # in case we got too many results due to a large last page
            results = results[:limit]
        return results, total

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
