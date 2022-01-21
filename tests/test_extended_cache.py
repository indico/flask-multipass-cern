from datetime import datetime, timedelta

import pytest

from extended_cache import ExtendedCache
from tests.conftest import MemoryCache


@pytest.fixture
def cache():
    cache = MemoryCache()
    return ExtendedCache(cache)


def test_timestamps(cache):
    cache.set('foo', 'bar', 2000, 1000)
    cache.set('baz', 'qux', 2000)

    assert cache.cache.data.get('foo') is not None
    assert cache.cache.data.get('foo:timestamp') is not None
    assert cache.cache.data.get('baz') is not None
    assert cache.cache.data.get('baz:timestamp') is None


def test_timestamp(cache, freeze_time):
    test_timestamp = datetime(2008, 9, 10, 10, 28, 0, 0)
    freeze_time(test_timestamp)

    cache.set('foo', 'bar', 2000, 1000)
    cache_entry_timestamp = cache.get('foo:timestamp')

    assert cache_entry_timestamp == test_timestamp


def test_should_refresh_false(cache):
    cache.set('foo', 'bar', 2000, 10)
    assert cache.should_refresh('foo') == False


def test_should_refresh_true(cache, freeze_time):
    cache.set('foo', 'bar', 2000, 10)
    freeze_time(datetime.now() + timedelta(seconds=100))

    assert cache.should_refresh('foo') == True


def test_should_refresh_miss(cache):
    should_refresh_miss = cache.should_refresh('miss')
    assert should_refresh_miss == True
