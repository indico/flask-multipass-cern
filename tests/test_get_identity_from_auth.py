from unittest.mock import MagicMock

import pytest
from requests.exceptions import HTTPError


@pytest.fixture
def mock_fetch_identity_data_fail(mocker):
    fetch_identity_data = mocker.patch('flask_multipass_cern.CERNIdentityProvider._fetch_identity_data')
    fetch_identity_data.side_effect = HTTPError()
    return fetch_identity_data


@pytest.fixture
def auth_info():
    auth_info = MagicMock()
    auth_info.data = {
        'sub': 'testupn',
        'given_name': 'Jean',
        'family_name': 'Dupont',
        'name': 'Jean Dupont',
        'email': 'jean.dupont@example.com',
        'cern_person_id': '123',
    }
    return auth_info


def test_fetch_identity_data_fails_cache_miss(provider, auth_info, mock_fetch_identity_data_fail):
    with pytest.raises(HTTPError):
        provider.get_identity_from_auth(auth_info)


def test_fetch_identity_data_fails_cache_hit(provider, auth_info, mock_fetch_identity_data_fail):
    provider.cache.set('flask-multipass-cern:cip:phone:testupn', '12341234')
    provider.cache.set('flask-multipass-cern:cip:affiliation:testupn', 'faketitute')

    result = provider.get_identity_from_auth(auth_info)

    assert all(k in result.data for k in ['first_name', 'last_name', 'email', 'phone', 'affiliation'])


def test_fields_mismatch(provider, auth_info, mocker):
    logger_spy = mocker.spy(provider.logger, 'warning')
    mock_authz_data = {
        'upn': 'testupn1',
        'firstName': 'John',
        'lastName': 'Doe',
        'primaryAccountEmail': 'john.doe@example.com',
        'cernPersonId': '124',
    }

    provider._compare_data(auth_info.data, mock_authz_data)

    assert logger_spy.call_count == 5
