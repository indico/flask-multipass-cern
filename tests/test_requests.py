import httpretty
import pytest
import requests
from flask import Flask
from flask_multipass import Multipass
from indico.core.cache import make_scoped_cache
from requests.sessions import Session

from flask_multipass_cern import OIDC_RETRY_COUNT, CERNIdentityProvider, retry_config


@pytest.fixture()
def flask_app():
    app = Flask('test')
    Multipass(app)
    with app.app_context():
        yield app


@pytest.fixture()
def httpretty_enabled():
    with httpretty.enabled():
        yield httpretty

    httpretty.disable()


@pytest.fixture()
def mock_get_api_session(mocker):
    mock_session = mocker.patch('flask_multipass_cern.CERNIdentityProvider._get_api_session')
    mock_session.return_value = Session()
    mock_session.return_value.mount('https://authorization-service-api.web.cern.ch', retry_config)

    return mock_session


@pytest.fixture()
def provider():
    settings = {
        'authlib_args': {'client_id': 'test', 'client_secret': 'test'},
        'cache': make_scoped_cache('flask-multipass-cern')
    }
    return CERNIdentityProvider(None, 'cip', settings)


def test_get_identity_groups_retry(flask_app, provider, httpretty_enabled, mock_get_api_session):
    authz_api = provider.settings.get('authz_api')
    test_uri = f'{authz_api}/api/v1.0/IdentityMembership/1/precomputed'

    httpretty.register_uri(httpretty.GET, test_uri, status=503)
    try:
        provider.get_identity_groups(1)
    except requests.exceptions.HTTPError:
        assert len(httpretty.latest_requests()) == OIDC_RETRY_COUNT + 1


def test_get_identity_data_retry(flask_app, provider, httpretty_enabled, mock_get_api_session):
    authz_api = provider.settings.get('authz_api')
    test_uri = f'{authz_api}/api/v1.0/Identity/1'

    httpretty.register_uri(httpretty.GET, test_uri, status=503)
    try:
        provider._get_identity_data(1)
    except requests.exceptions.HTTPError:
        assert len(httpretty.latest_requests()) == OIDC_RETRY_COUNT + 1

def test_get_group_data_retry(flask_app, provider, httpretty_enabled, mock_get_api_session):
    authz_api = provider.settings.get('authz_api')
    test_uri = f'{authz_api}/api/v1.0/Group'

    httpretty.register_uri(httpretty.GET, test_uri, status=503)
    try:
        provider._get_group_data('mygroup')
    except requests.exceptions.HTTPError:
        assert len(httpretty.latest_requests()) == OIDC_RETRY_COUNT + 1


def test_fetch_all_retry(flask_app, provider, httpretty_enabled, mock_get_api_session):
    authz_api_base = provider.settings.get('authz_api')
    test_uri = '/api/v1.0/Identity'

    with provider._get_api_session() as api_session:
        httpretty.register_uri(httpretty.GET, f'{authz_api_base}{test_uri}', status=503)
        try:
            provider._fetch_all(api_session, test_uri, {})
        except requests.exceptions.HTTPError:
            assert len(httpretty.latest_requests()) == OIDC_RETRY_COUNT + 1
