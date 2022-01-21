from datetime import datetime, timedelta

import httpretty
import pytest
from flask_multipass import IdentityInfo
from requests import Session
from requests.exceptions import RequestException

from tests.conftest import MemoryCache


@pytest.fixture
def mock_get_api_session(mocker):
    get_api_session = mocker.patch('flask_multipass_cern.CERNIdentityProvider._get_api_session')
    get_api_session.return_value = Session()
    return get_api_session


@pytest.fixture
def spy_cache_set(mocker):
    return mocker.spy(MemoryCache, 'set')


@pytest.fixture
def mock_data():
    return {
        'primaryAccountEmail': 'test@cern.ch',
        'upn': 'guineapig',
        'displayName': 'Guinea Pig',
        'lastName': 'Pig',
        'firstName': 'Guinea',
        'instituteName': 'CERN',
        'telephone1': '1234',
    }


@pytest.fixture
def mock_data_map():
    return {
        'primaryAccountEmail': 'email',
        'lastName': 'last_name',
        'firstName': 'first_name',
        'instituteName': 'affiliation',
        'telephone1': 'phone',
    }


def test_search_identities_cache_miss(provider, mock_get_api_session, httpretty_enabled):
    test_uri = f'{provider.settings.get("authz_api")}/api/v1.0/Identity'
    httpretty.register_uri(httpretty.GET, test_uri, status=503)
    with pytest.raises(RequestException):
        provider.search_identities_ex({'primaryAccountEmail': {'test@cern.ch'}}, True)


def test_search_identities_cache_hit_fresh(provider, mock_data, mock_data_map):
    cache_key = 'flask-multipass-cern:cip:email-identities:test@cern.ch'
    provider.cache.set(cache_key, ([mock_data], 1), 2000, 2000)
    identities = provider.search_identities_ex({'primaryAccountEmail': {'test@cern.ch'}}, True)

    for data_key, identities_key in mock_data_map.items():
        assert mock_data[data_key] == identities[0][0].data.get(identities_key)
    assert isinstance(identities[0][0], IdentityInfo)
    assert identities[1] == 1


def test_search_identities_cache_hit_stale(
    provider,
    mock_get_api_session,
    mock_data,
    mock_data_map,
    freeze_time,
    httpretty_enabled
):
    test_uri = f'{provider.settings.get("authz_api")}/api/v1.0/Identity'
    httpretty.register_uri(httpretty.GET, test_uri, status=503)
    cache_key = 'flask-multipass-cern:cip:email-identities:test@cern.ch'
    provider.cache.set(cache_key, ([mock_data], 1), 2000, 10)
    freeze_time(datetime.now() + timedelta(seconds=100))

    identities = provider.search_identities_ex({'primaryAccountEmail': {'test@cern.ch'}}, True)

    for data_key, identities_key in mock_data_map.items():
        assert mock_data[data_key] == identities[0][0].data.get(identities_key)
    assert isinstance(identities[0][0], IdentityInfo)
    assert identities[1] == 1
