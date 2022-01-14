from datetime import datetime
from unittest.mock import MagicMock

import httpretty
import pytest
from requests import Session

from indico.core.cache import IndicoCache

from flask_multipass_cern import CERNGroup


@pytest.fixture()
def mock_get_api_session(mocker):
    get_api_session = mocker.patch('flask_multipass_cern.CERNIdentityProvider._get_api_session')
    get_api_session.return_value = Session()
    return get_api_session


@pytest.fixture()
def mock_get_identity_groups(mocker):
    get_identity_groups = mocker.patch('flask_multipass_cern.CERNIdentityProvider.get_identity_groups')
    group = MagicMock()
    group.name = 'cern users'
    get_identity_groups.return_value = {group}
    return get_identity_groups


@pytest.fixture()
def mock_cache_set(mocker):
    return mocker.spy(IndicoCache, 'set')


def test_has_member_cache(provider, mock_get_identity_groups):
    test_group = CERNGroup(provider, 'cern users')
    test_group.has_member('12345')

    assert(test_group.provider.cache.get('flask-multipass-cern:cip:groups:12345'))
    assert(test_group.provider.cache.get('flask-multipass-cern:cip:groups:12345:timestamp'))


def test_has_member_cache_miss(provider, mock_get_identity_groups, mock_cache_set):
    test_group = CERNGroup(provider, 'cern users')
    test_group.has_member('12345')

    assert mock_cache_set.call_count == 2


def test_has_member_cache_hit(provider, mock_get_identity_groups):
    test_group = CERNGroup(provider, 'cern users')
    test_group.provider.cache.set('flask-multipass-cern:cip:groups:12345', 'cern users')
    test_group.provider.cache.set('flask-multipass-cern:cip:groups:12345:timestamp', datetime.now())
    test_group.has_member('12345')

    assert not mock_get_identity_groups.called


def test_has_member_request_returns_503(provider, httpretty_enabled, mock_get_api_session):
    test_group = CERNGroup(provider, 'cern users')
    authz_api = provider.settings.get('authz_api')
    test_uri = f'{authz_api}/api/v1.0/IdentityMembership/12345/precomputed'

    httpretty.register_uri(httpretty.GET, test_uri, status=503)

    test_group.has_member('12345')
