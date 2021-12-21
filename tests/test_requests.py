import json
from unittest.mock import patch

import httpretty
import pytest
import requests
from flask import Flask
from flask_multipass import Multipass
from requests.sessions import Session

from flask_multipass_cern import OIDC_RETRY_COUNT, CERNIdentityProvider


@patch('flask_multipass_cern.CERNIdentityProvider._get_api_session')
def test_get_identity_groups_retry(mock_get_api_session):
    mock_get_api_session.return_value = Session()
    app = Flask('test')
    Multipass(app)

    with app.app_context():
        provider = CERNIdentityProvider(None, 'cip', {'authlib_args': {'client_id': 'test', 'client_secret': 'test'}})
        authz_api = provider.settings.get('authz_api')
        test_uri = f'{authz_api}/api/v1.0/IdentityMembership/1/precomputed'

        with httpretty.enabled():
            httpretty.register_uri(httpretty.GET, test_uri, status=503)
            try:
                provider.get_identity_groups(1)
            except requests.exceptions.HTTPError:
                assert len(httpretty.latest_requests()) == OIDC_RETRY_COUNT + 1


@patch('flask_multipass_cern.CERNIdentityProvider._get_api_session')
def test_get_identity_data_retry(mock_get_api_session):
    mock_get_api_session.return_value = Session()
    app = Flask('test')
    Multipass(app)

    with app.app_context():
        provider = CERNIdentityProvider(None, 'cip', {'authlib_args': {'client_id': 'test', 'client_secret': 'test'}})
        authz_api = provider.settings.get('authz_api')
        test_uri = f'{authz_api}/api/v1.0/Identity/1'

        with httpretty.enabled():
            httpretty.register_uri(httpretty.GET, test_uri, status=503)
            try:
                provider._get_identity_data(1)
            except requests.exceptions.HTTPError:
                assert len(httpretty.latest_requests()) == OIDC_RETRY_COUNT + 1

@patch('flask_multipass_cern.CERNIdentityProvider._get_api_session')
def test_get_group_data_retry(mock_get_api_session):
    mock_get_api_session.return_value = Session()
    app = Flask('test')
    Multipass(app)

    with app.app_context():
        provider = CERNIdentityProvider(None, 'cip', {'authlib_args': {'client_id': 'test', 'client_secret': 'test'}})
        authz_api = provider.settings.get('authz_api')
        test_uri = f'{authz_api}/api/v1.0/Group'

        with httpretty.enabled():
            httpretty.register_uri(httpretty.GET, test_uri, status=503)
            try:
                provider._get_group_data('mygroup')
            except requests.exceptions.HTTPError:
                assert len(httpretty.latest_requests()) == OIDC_RETRY_COUNT + 1


@patch('flask_multipass_cern.CERNIdentityProvider._get_api_session')
def test_fetch_all_retry(mock_get_api_session):
    mock_get_api_session.return_value = Session()
    app = Flask('test')
    Multipass(app)

    with app.app_context():
        provider = CERNIdentityProvider(None, 'cip', {'authlib_args': {'client_id': 'test', 'client_secret': 'test'}})
        authz_api_base = provider.settings.get('authz_api')
        test_uri = '/api/v1.0/Identity'

        with httpretty.enabled():
            with provider._get_api_session() as api_session:
                httpretty.register_uri(httpretty.GET, f'{authz_api_base}{test_uri}', status=503)
                try:
                    provider._fetch_all(api_session, test_uri, {})
                except requests.exceptions.HTTPError:
                    assert len(httpretty.latest_requests()) == OIDC_RETRY_COUNT + 1
