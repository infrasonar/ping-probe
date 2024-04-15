import logging
from ..icmp import async_ping2
from libprobe.asset import Asset
from libprobe.exceptions import CheckException, NoCountException
from ..utils import check_config


DEFAULT_PING_COUNT = 5  # (1 - 9)
DEFAULT_PING_INTERVAL = 1  # (1s - 9s)
DEFAULT_PING_TIMEOUT = 10
TYPE_NAME = 'icmp'
ITEM_NAME = 'ping'


def get_item(itm, name, address, count, messages):
    max_time = None
    min_time = None

    if itm.is_alive:
        max_time = itm.max_rtt / 1000  # float (s)
        min_time = itm.min_rtt / 1000  # float (s)

    return {
        'name': name,
        'address': address,
        'count': count,
        'dropped': itm.packets_sent - itm.packets_received,  # int
        'maxTime': max_time,  # float (s) or None
        'minTime': min_time,  # float(s) or None
        'messages': messages,
    }


def get_state(data, address, count, messages):
    state = {TYPE_NAME: [get_item(data, ITEM_NAME, address, count, messages)]}
    return state


async def check_ping(
        asset: Asset,
        asset_config: dict,
        config: dict) -> dict:
    address = config.get('address')
    if not address:
        address = asset.name
    count = config.get('count', DEFAULT_PING_COUNT)
    interval = config.get('interval', DEFAULT_PING_INTERVAL)
    timeout = config.get('timeout', DEFAULT_PING_TIMEOUT)
    check_config(count, interval)

    catch_messages = []

    logging.debug(
        f"ping {address}; "
        f"count: {count} interval: {interval} timeout: {timeout}; {asset}")

    try:
        data = await async_ping2(
            catch_messages,
            address,
            count=count,
            interval=interval,
            timeout=timeout,
        )
    except Exception as e:
        error_msg = str(e) or type(e).__name__
        raise CheckException(f"ping failed: {error_msg}")

    result = get_state(data, address, count, catch_messages)
    if data.packets_sent > 0 and data.packets_received == 0:
        raise NoCountException('all packages dropped', result)

    return result
