from datetime import datetime

import freezegun
import httpretty
import pytest
from flask import Flask
from flask_multipass import Multipass
from requests.sessions import Session

from flask_multipass_cern import CERNIdentityProvider, retry_config


class MemoryCacheEntry:
    def __init__(self, value, timeout=0):
        self.value = value
        self.timeout = timeout or None
        self.timestamp = datetime.now()


class MemoryCache:
    """Simple dict-based in memory cache with expiration."""

    def __init__(self):
        self.data = {}

    def get(self, key, default=None):
        entry = self.data.get(key, default)

        if entry is None or not isinstance(entry, MemoryCacheEntry):
            return default
        elif entry.timeout:
            if (datetime.now() - entry.timestamp).total_seconds() >= entry.timeout:
                del self.data[key]
                return default
        return entry.value

    def set(self, key, value, timeout=0):
        self.data[key] = MemoryCacheEntry(value, timeout)


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


@pytest.fixture(autouse=True)
def flask_app():
    app = Flask(__name__)
    Multipass(app)
    with app.app_context():
        yield app


@pytest.fixture
def provider():
    settings = {
        'authlib_args': {'client_id': 'test', 'client_secret': 'test'},
        'cache': MemoryCache,
    }
    return CERNIdentityProvider(None, 'cip', settings)


@pytest.fixture
def freeze_time():
    freezers = []

    def _freeze_time(time_to_freeze):
        freezer = freezegun.freeze_time(time_to_freeze)
        freezer.start()
        freezers.append(freezer)

    yield _freeze_time
    for freezer in reversed(freezers):
        freezer.stop()
