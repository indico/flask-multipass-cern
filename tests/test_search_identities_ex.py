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


@pytest.mark.usefixtures('mock_get_api_session', 'httpretty_enabled')
def test_search_identities_cache_miss(provider):
    test_uri = f'{provider.settings.get("authz_api")}/api/v1.0/Identity'
    httpretty.register_uri(httpretty.GET, test_uri, status=503)
    with pytest.raises(RequestException):
        provider.search_identities_ex({'primaryAccountEmail': {'test@cern.ch'}}, True)


def test_search_identities_cache_hit_fresh(provider, mock_data):
    cache_key = 'flask-multipass-cern:cip:email-identities:test@cern.ch'
    provider.cache.set(cache_key, ([mock_data], 1), 2000, 2000)
    identities = provider.search_identities_ex({'primaryAccountEmail': {'test@cern.ch'}}, True)

    for identities_key, data_key in provider.settings.get('mapping').items():
        assert mock_data[data_key] == identities[0][0].data.get(identities_key)
    assert isinstance(identities[0][0], IdentityInfo)
    assert identities[1] == 1


@pytest.mark.usefixtures('mock_get_api_session', 'httpretty_enabled')
def test_search_identities_cache_hit_stale(provider, mock_data, freeze_time):
    test_uri = f'{provider.settings.get("authz_api")}/api/v1.0/Identity'
    httpretty.register_uri(httpretty.GET, test_uri, status=503)
    cache_key = 'flask-multipass-cern:cip:email-identities:test@cern.ch'
    provider.cache.set(cache_key, ([mock_data], 1), 2000, 10)
    freeze_time(datetime.now() + timedelta(seconds=100))

    identities = provider.search_identities_ex({'primaryAccountEmail': {'test@cern.ch'}}, True)

    for identities_key, data_key in provider.settings.get('mapping').items():
        assert mock_data[data_key] == identities[0][0].data.get(identities_key)
    assert isinstance(identities[0][0], IdentityInfo)
    assert identities[1] == 1
