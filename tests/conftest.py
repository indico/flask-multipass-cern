import httpretty
import pytest
from requests.sessions import Session

from flask_multipass_cern import CERNIdentityProvider, retry_config


class MemoryCache:
    def __init__(self):
        self.data = {}

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value, timeout=0):
        self.data[key] = value


@pytest.fixture
def httpretty_enabled():
    with httpretty.enabled():
        yield httpretty
    httpretty.disable()


@pytest.fixture
def mock_get_api_session(mocker):
    mock_session = mocker.patch('flask_multipass_cern.CERNIdentityProvider._get_api_session')
    mock_session.return_value = Session()
    mock_session.return_value.mount('https://authorization-service-api.web.cern.ch', retry_config)
    return mock_session


@pytest.fixture
def provider():
    settings = {
        'authlib_args': {'client_id': 'test', 'client_secret': 'test'},
        'cache': MemoryCache
    }
    return CERNIdentityProvider(None, 'cip', settings)
