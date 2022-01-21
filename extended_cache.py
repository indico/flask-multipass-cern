# This file is part of Flask-Multipass-CERN.
# Copyright (C) 2020 - 2022 CERN
#
# Flask-Multipass-CERN is free software; you can redistribute
# it and/or modify it under the terms of the MIT License; see
# the LICENSE file for more details.

from datetime import datetime
from importlib import import_module


class ExtendedCacheInitException(Exception):
    """Exception initializing extended cache."""
    pass


class ExtendedCache:
    def __init__(self, cache):
        self.cache = self._init_cache(cache)

    def _init_cache(self, cache):
        if cache is None:
            raise ExtendedCacheInitException
        elif callable(cache):
            return cache()
        elif isinstance(cache, str):
            module_path, class_name = cache.rsplit('.', 1)
            module = import_module(module_path)
            return getattr(module, class_name)
        else:
            return cache

    def get(self, key, default=None):
        return self.cache.get(key, default)

    def set(self, key, value, timeout=0, refresh_timeout=None):
        self.cache.set(key, value, timeout)
        if refresh_timeout:
            self.cache.set(f'{key}:timestamp', datetime.now(), refresh_timeout)

    def should_refresh(self, key):
        return self.cache.get(f'{key}:timestamp') is None
