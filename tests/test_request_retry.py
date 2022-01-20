import httpretty
import pytest
import requests
from flask import Flask
from flask_multipass import Multipass

from flask_multipass_cern import HTTP_RETRY_COUNT


@pytest.fixture
def flask_app():
    app = Flask('test')
    Multipass(app)
    with app.app_context():
        yield app


def test_get_identity_groups_retry(flask_app, provider, httpretty_enabled, mock_get_api_session):
    authz_api = provider.settings.get('authz_api')
    test_uri = f'{authz_api}/api/v1.0/IdentityMembership/1/precomputed'
    httpretty.register_uri(httpretty.GET, test_uri, status=503)

    try:
        provider.get_identity_groups(1)
    except requests.exceptions.HTTPError:
        assert len(httpretty.latest_requests()) == HTTP_RETRY_COUNT + 1


def test_get_identity_data_retry(flask_app, provider, httpretty_enabled, mock_get_api_session):
    authz_api = provider.settings.get('authz_api')
    test_uri = f'{authz_api}/api/v1.0/Identity/1'
    httpretty.register_uri(httpretty.GET, test_uri, status=503)

    try:
        provider._get_identity_data(1)
    except requests.exceptions.HTTPError:
        assert len(httpretty.latest_requests()) == HTTP_RETRY_COUNT + 1


def test_get_group_data_retry(flask_app, provider, httpretty_enabled, mock_get_api_session):
    authz_api = provider.settings.get('authz_api')
    test_uri = f'{authz_api}/api/v1.0/Group'
    httpretty.register_uri(httpretty.GET, test_uri, status=503)

    try:
        provider._get_group_data('mygroup')
    except requests.exceptions.HTTPError:
        assert len(httpretty.latest_requests()) == HTTP_RETRY_COUNT + 1


def test_fetch_all_retry(flask_app, provider, httpretty_enabled, mock_get_api_session):
    authz_api_base = provider.settings.get('authz_api')
    test_uri = '/api/v1.0/Identity'

    with provider._get_api_session() as api_session:
        httpretty.register_uri(httpretty.GET, f'{authz_api_base}{test_uri}', status=503)
        try:
            provider._fetch_all(api_session, test_uri, {})
        except requests.exceptions.HTTPError:
            assert len(httpretty.latest_requests()) == HTTP_RETRY_COUNT + 1
