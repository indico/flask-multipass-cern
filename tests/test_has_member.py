from datetime import datetime

import pytest
from requests import Session
from requests.exceptions import RequestException

from flask_multipass_cern import CERNGroup
from tests.conftest import MemoryCache


@pytest.fixture
def mock_get_api_session(mocker):
    get_api_session = mocker.patch('flask_multipass_cern.CERNIdentityProvider._get_api_session')
    get_api_session.return_value = Session()
    return get_api_session


@pytest.fixture
def mock_fetch_identity_group_names(mocker):
    get_identity_groups = mocker.patch('flask_multipass_cern.CERNIdentityProvider._fetch_identity_group_names')
    get_identity_groups.return_value = {'cern users'}
    return get_identity_groups


@pytest.fixture
def mock_get_identity_groups_fail(mocker):
    get_identity_groups = mocker.patch('flask_multipass_cern.CERNIdentityProvider._fetch_identity_group_names')
    get_identity_groups.side_effect = RequestException()
    return get_identity_groups


@pytest.fixture
def spy_cache_set(mocker):
    return mocker.spy(MemoryCache, 'set')


@pytest.mark.usefixtures('mock_fetch_identity_group_names')
def test_has_member_cache(provider):
    test_group = CERNGroup(provider, 'cern users')
    test_group.has_member('12345')

    assert test_group.provider.cache.get('flask-multipass-cern:cip:groups:12345')
    assert test_group.provider.cache.get('flask-multipass-cern:cip:groups:12345:timestamp')


@pytest.mark.usefixtures('mock_fetch_identity_group_names')
def test_has_member_cache_miss(provider, spy_cache_set):
    test_group = CERNGroup(provider, 'cern users')
    test_group.has_member('12345')

    assert spy_cache_set.call_count == 2


def test_has_member_cache_hit(provider, mock_fetch_identity_group_names):
    test_group = CERNGroup(provider, 'cern users')
    test_group.provider.cache.set('flask-multipass-cern:cip:groups:12345', 'cern users')
    test_group.provider.cache.set('flask-multipass-cern:cip:groups:12345:timestamp', datetime.now())
    test_group.has_member('12345')

    assert not mock_fetch_identity_group_names.called


@pytest.mark.usefixtures('mock_fetch_identity_group_names')
def test_has_member_request_fails(provider, mock_get_identity_groups_fail):
    test_group = CERNGroup(provider, 'cern users')
    res = test_group.has_member('12345')

    assert mock_get_identity_groups_fail.called
    assert res is False
