# This file is part of Flask-Multipass-CERN.
# Copyright (C) 2020 - 2021 CERN
#
# Flask-Multipass-CERN is free software; you can redistribute
# it and/or modify it under the terms of the MIT License; see
# the LICENSE file for more details.

from functools import wraps
from importlib import import_module
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
        super().__init__(*args, **kwargs)
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

    def get_members(self):
        assert '/' not in self.name
        with self.provider._get_api_session() as api_session:
            group_data = self.provider._get_group_data(self.name)
            if group_data is None:
                return
            gid = group_data['id']

            params = {
                'limit': 5000,
                'field': [
                    'upn',
                    'firstName',
                    'lastName',
                    'instituteName',
                    'telephone1',
                    'primaryAccountEmail',
                ],
                'recursive': 'true'
            }
            results = self.provider._fetch_all(api_session, f'/api/v1.0/Group/{gid}/memberidentities', params)[0]
        for res in results:
            del res['id']  # id is always included
            self.provider._fix_phone(res)
            yield IdentityInfo(self.provider, res.pop('upn'), **res)

    def has_member(self, identifier):
        cache_key = f'flask-multipass-cern:{self.provider.name}:groups:{identifier}'
        all_groups = self.provider.cache and self.provider.cache.get(cache_key)
        if all_groups is None:
            all_groups = {g.name.lower() for g in self.provider.get_identity_groups(identifier)}
            if self.provider.cache:
                self.provider.cache.set(cache_key, all_groups, 1800)
        if self.provider.settings['cern_users_group'] and self.name.lower() == 'cern users':
            return self.provider.settings['cern_users_group'].lower() in all_groups
        return self.name.lower() in all_groups


class CERNIdentityProvider(IdentityProvider):
    supports_refresh = False
    supports_get = False
    supports_search = True
    supports_search_ex = True
    supports_groups = True
    supports_get_identity_groups = True
    group_class = CERNGroup

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.authlib_client = _authlib_oauth.register(self.name + '-idp', **self.authlib_settings)
        self.settings.setdefault('cache', None)
        self.settings.setdefault('extra_search_filters', [])
        self.settings.setdefault('authz_api', 'https://authorization-service-api.web.cern.ch')
        self.settings.setdefault('phone_prefix', '+412276')
        self.settings.setdefault('cern_users_group', None)
        self.cache = self._init_cache()
        if not self.settings.get('mapping'):
            # usually mapping is empty, in that case we set some defaults
            self.settings['mapping'] = {
                'first_name': 'firstName',
                'last_name': 'lastName',
                'affiliation': 'instituteName',
                'phone': 'telephone1',
                'email': 'primaryAccountEmail',
            }

    @property
    def authlib_settings(self):
        settings = dict(self.settings['authlib_args'])
        settings.setdefault('server_metadata_url', CERN_OIDC_WELLKNOWN_URL)
        return settings

    def _init_cache(self):
        if self.settings['cache'] is None:
            return None
        elif callable(self.settings['cache']):
            return self.settings['cache']()
        elif isinstance(self.settings['cache'], str):
            module_path, class_name = self.settings['cache'].rsplit('.', 1)
            module = import_module(module_path)
            return getattr(module, class_name)
        else:
            return self.settings['cache']

    @property
    def authz_api_base(self):
        return self.settings['authz_api'].rstrip('/')

    def _fix_phone(self, data):
        phone = data.get('telephone1')
        if not phone or phone.startswith('+'):
            return
        data['telephone1'] = self.settings['phone_prefix'] + phone

    def get_identity_from_auth(self, auth_info):
        data = self._fetch_identity_data(auth_info)
        self._fix_phone(data)
        return IdentityInfo(self, data.pop('upn'), **data)

    def search_identities(self, criteria, exact=False):
        return iter(self.search_identities_ex(criteria, exact=exact)[0])

    @memoize_request
    def search_identities_ex(self, criteria, exact=False, limit=None):
        use_cache = self.cache and exact and limit is None and len(criteria) == 1 and 'primaryAccountEmail' in criteria
        if use_cache:
            emails_key = '-'.join(sorted(x.lower() for x in criteria['primaryAccountEmail']))
            cache_key = f'flask-multipass-cern:{self.name}:email-identities:{emails_key}'
            cached_data = self.cache.get(cache_key)
            if cached_data:
                return [IdentityInfo(self, res['upn'], **res) for res in cached_data[0]], cached_data[1]

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
        api_criteria = [f'{k}:{op}:{v}' for k, v in criteria.items()]
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
                'telephone1',
                'primaryAccountEmail',
            ],
        }

        with self._get_api_session() as api_session:
            results, total = self._fetch_all(api_session, '/api/v1.0/Identity', params, limit=limit)

        identities = []
        cache_data = []
        for res in results:
            if not res['upn']:
                total -= 1
                continue
            del res['id']
            self._fix_phone(res)
            identities.append(IdentityInfo(self, res['upn'], **res))
            if use_cache:
                cache_data.append(res)
        if use_cache:
            self.cache.set(cache_key, (cache_data, total), 3600)
        return identities, total

    def get_identity_groups(self, identifier):
        assert '/' not in identifier
        with self._get_api_session() as api_session:
            resp = api_session.get(f'{self.authz_api_base}/api/v1.0/IdentityMembership/{identifier}/precomputed')
            if resp.status_code == 404:
                return set()
            resp.raise_for_status()
            results = resp.json()['data']
        return {self.group_class(self, res['groupIdentifier']) for res in results}

    def get_group(self, name):
        return self.group_class(self, name)

    def search_groups(self, name, exact=False):
        op = 'eq' if exact else 'contains'
        params = {
            'limit': 5000,
            'filter': [f'groupIdentifier:{op}:{name}'],
            'field': ['groupIdentifier'],
        }
        with self._get_api_session() as api_session:
            results = self._fetch_all(api_session, '/api/v1.0/Group', params)[0]
        rv = {self.group_class(self, res['groupIdentifier']) for res in results}
        if (
            self.settings['cern_users_group'] and
            (name.lower() == 'cern users' or (not exact and name.lower() in 'cern users'))
        ):
            rv.add(self.group_class(self, 'CERN Users'))
        return rv

    @memoize_request
    def _get_api_session(self):
        cache_key = f'flask-multipass-cern:{self.name}:api-token'
        token = self.cache and self.cache.get(cache_key)
        if token:
            return OAuth2Session(token=token)
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
        if self.cache:
            self.cache.set(cache_key, oauth_session.token, oauth_session.token['expires_in'] - 30)
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
                'telephone1',
                'primaryAccountEmail',
            ],
        }
        resp = self.authlib_client.get(f'{self.authz_api_base}/api/v1.0/Identity/current', token=user_api_token,
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
            'filter': [f'groupIdentifier:eq:{name}'],
            'field': ['id', 'groupIdentifier'],
        }
        with self._get_api_session() as api_session:
            resp = api_session.get(f'{self.authz_api_base}/api/v1.0/Group', params=params)
            resp.raise_for_status()
            data = resp.json()
        if len(data['data']) != 1:
            return None
        return data['data'][0]
