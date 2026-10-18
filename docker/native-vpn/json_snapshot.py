"""Bounded reads of continuously replaced, owned fixture telemetry snapshots."""

import json
import math
from pathlib import Path
import time


MAX_BYTES = 1024 * 1024
ATTEMPTS = 10
RETRY_SECONDS = .1


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate snapshot object key')
        value[key] = item
    return value


def _constant(_value):
    raise ValueError('nonfinite snapshot number')


def _float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError('nonfinite snapshot number')
    return result


def _read(path, expected):
    path = Path(path)
    for attempt in range(ATTEMPTS):
        try:
            with path.open('rb') as stream:
                raw = stream.read(MAX_BYTES + 1)
        except FileNotFoundError:
            if attempt + 1 == ATTEMPTS:
                raise
            time.sleep(RETRY_SECONDS)
            continue
        if len(raw) > MAX_BYTES:
            raise ValueError('snapshot exceeds one MiB')
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_object,
                           parse_constant=_constant, parse_float=_float)
        if type(value) is not expected:
            raise ValueError('snapshot must be a JSON ' + ('object' if expected is dict else 'array'))
        return value
    raise AssertionError('snapshot read attempts exhausted without a result')


def read_object(path):
    """Read one current object; only absence is retried, without cached/default data."""
    return _read(path, dict)


def read_array(path):
    """Read one current array; callers still enforce their nonempty/value assertions."""
    return _read(path, list)
