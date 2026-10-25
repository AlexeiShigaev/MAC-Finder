import os

import pytest

from app.snmp.models import QueryOID
from app.snmp.oid_query import get_oid_from_to


pytestmark = pytest.mark.integration


def _query_from_env(**overrides) -> QueryOID:
    host = os.environ.get("SNMP_TEST_HOST")
    if not host:
        pytest.skip("SNMP_TEST_HOST not set")

    params = {
        "host": host,
        "community": os.environ.get("SNMP_TEST_COMMUNITY", "public"),
        "snmp_ver": int(os.environ.get("SNMP_TEST_SNMP_VER", "1")),
        "timeout": 3,
        "retries": 1,
    }
    params.update(overrides)
    return QueryOID(**params)


async def test_sysdescr_walk():
    """Базовый прогон: sysDescr должен вернуться, error — None."""
    query = _query_from_env(
        oid_start=".1.3.6.1.2.1.1.1",
        oid_stop=".1.3.6.1.2.1.1.7",
    )

    result = await get_oid_from_to(query)

    assert result.error is None
    assert result.count > 0
    # проверь, что вернулись осмысленные типы
    for oid, value in result.result_list:
        assert value is not None


async def test_oid_stop_is_exclusive():
    """oid_stop должен НЕ попадать в результат."""
    query = _query_from_env(
        oid_start=".1.3.6.1.2.1.1.1",
        oid_stop=".1.3.6.1.2.1.1.7",
    )

    result = await get_oid_from_to(query)

    for oid, _ in result.result_list:
        assert not str(oid).startswith(".1.3.6.1.2.1.1.7"), \
            "oid_stop попал в результат: {}".format(oid)


async def test_end_of_mib_stops_walk():
    """Если oid_stop за пределами MIB — не должно быть бесконечного цикла."""
    query = _query_from_env(
        oid_start=".1.3.6.1.2.1.1.1",
        oid_stop=".1.3.6.1.4.1",  # далеко за пределами sysDescr
        timeout=2,
        retries=0,
    )

    result = await get_oid_from_to(query)

    # не должно зависнуть; error либо None, либо осмысленная строка
    assert result.error is None or isinstance(result.error, str)


async def test_nonexistent_oid_returns_empty_or_error():
    """Несуществующий OID: либо error, либо пустой список — но не падение."""
    query = _query_from_env(
        oid_start=".1.3.6.1.4.1.999999.1",
        oid_stop=".1.3.6.1.4.1.999999.2",
        timeout=2,
        retries=0,
    )

    result = await get_oid_from_to(query)

    # главное — не упало и не зависло
    assert result.error is None or isinstance(result.error, str)


async def test_timeout_is_respected():
    """С таймаутом 1 сек на медленном свиче — не должно висеть минуту."""
    import time
    query = _query_from_env(
        oid_start=".1.3.6.1.2.1.1.1",
        oid_stop=".1.3.6.1.2.1.1.7",
        timeout=1,
        retries=0,
    )

    start = time.monotonic()
    result = await get_oid_from_to(query)
    elapsed = time.monotonic() - start

    # даже если таймаут — не больше 5 секунд (грубая проверка)
    assert elapsed < 5, "запрос занял {} сек — таймаут не работает".format(elapsed)