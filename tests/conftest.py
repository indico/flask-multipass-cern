import httpretty
import pytest
from requests.sessions import Session

from indico.core.cache import make_scoped_cache

from flask_multipass_cern import CERNIdentityProvider, retry_config


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
