from typing import List
import asyncio

from icmplib.sockets import ICMPv4Socket, ICMPv6Socket, AsyncSocket
from icmplib.models import ICMPRequest, Host
from icmplib.exceptions import (
    ICMPLibError,
    ICMPv6DestinationUnreachable,
    ICMPv6TimeExceeded,
    ICMPv4DestinationUnreachable,
    ICMPv4TimeExceeded,
    ICMPError)
from icmplib.utils import (
    is_hostname, is_ipv6_address, unique_identifier, async_resolve)


_MESSAGES_V6 = {
    0: 'Reserved',
    1: 'Destination Unreachable',
    2: 'Packet Too Big',
    3: 'Time Exceeded',
    4: 'Parameter Problem',
    128: 'Echo Request',
    129: 'Echo Reply',
    130: 'Multicast Listener Query',
    131: 'Multicast Listener Report',
    132: 'Multicast Listener Done',
    133: 'Router Solicitation',
    134: 'Router Advertisement',
    135: 'Neighbor Solicitation',
    136: 'Neighbor Advertisement',
    137: 'Redirect Message',
    138: 'Router Renumbering',
    139: 'ICMP Node Information Query',
    140: 'ICMP Node Information Response',
    141: 'Inverse Neighbor Discovery',
    142: 'Inverse Neighbor Discovery',
    144: 'Home Agent Address Discovery',
    145: 'Home Agent Address Discovery',
    146: 'Mobile Prefix Solicitation',
    147: 'Mobile Prefix Advertisement',
    157: 'Duplicate Address Request Code Suffix',
    158: 'Duplicate Address Confirmation Code Suffix',
    160: 'Extended Echo Request',
    161: 'Extended Echo Reply',
}

_MESSAGES_V4 = {
    0: 'Echo Reply',
    1: 'Unassigned',
    2: 'Unassigned',
    3: 'Destination Unreachable',
    4: 'Source Quench (Deprecated)',
    5: 'Redirect',
    6: 'Alternate Host Address (Deprecated)',
    7: 'Unassigned',
    8: 'Echo',
    9: 'Router Advertisement',
    10: 'Router Selection',
    11: 'Time Exceeded',
    12: 'Parameter Problem',
    13: 'Timestamp',
    14: 'Timestamp Reply',
    15: 'Information Request (Deprecated)',
    16: 'Information Reply (Deprecated)',
    17: 'Address Mask Request (Deprecated)',
    18: 'Address Mask Reply (Deprecated)',
    19: 'Reserved (for Security)',
    20: 'Reserved (for Robustness Experiment)',
    21: 'Reserved (for Robustness Experiment)',
    22: 'Reserved (for Robustness Experiment)',
    23: 'Reserved (for Robustness Experiment)',
    24: 'Reserved (for Robustness Experiment)',
    25: 'Reserved (for Robustness Experiment)',
    26: 'Reserved (for Robustness Experiment)',
    27: 'Reserved (for Robustness Experiment)',
    28: 'Reserved (for Robustness Experiment)',
    29: 'Reserved (for Robustness Experiment)',
    30: 'Traceroute (Deprecated)',
    31: 'Datagram Conversion Error (Deprecated)',
    32: 'Mobile Host Redirect (Deprecated)',
    33: 'IPv6 Where-Are-You (Deprecated)',
    34: 'IPv6 I-Am-Here (Deprecated)',
    35: 'Mobile Registration Request (Deprecated)',
    36: 'Mobile Registration Reply (Deprecated)',
    37: 'Domain Name Request (Deprecated)',
    38: 'Domain Name Reply (Deprecated)',
    39: 'SKIP (Deprecated)',
    40: 'Photuris',
    41: 'ICMP messages utilized by experimental mobility protocols such as Seamoby',
    42: 'Extended Echo Request',
    43: 'Extended Echo Reply',
    253: 'RFC3692-style Experiment 1',
    254: 'RFC3692-style Experiment 2',
}

def _raise_for_status(self, catch_messages: List[str]):
    '''
    Throw an exception if the reply is not an ICMP Echo Reply.
    Otherwise, do nothing.

    :raises DestinationUnreachable: If the destination is
        unreachable for some reason.
    :raises TimeExceeded: If the time to live field of the ICMP
        request has reached zero.
    :raises ICMPError: Raised for any other type and ICMP error
        code, except ICMP Echo Reply messages.

    '''
    if self._family == 6:
        catch_messages.append(_MESSAGES_V6.get(self._type, 'Unassigned'))
        if self._type == 1:
            raise ICMPv6DestinationUnreachable(self)

        if self._type == 3:
            raise ICMPv6TimeExceeded(self)
    else:
        catch_messages.append(_MESSAGES_V4.get(self._type, 'Unassigned'))
        if self._type == 3:
            raise ICMPv4DestinationUnreachable(self)

        if self._type == 11:
            raise ICMPv4TimeExceeded(self)

    # Type 0 and 129 are success "Echo", Type 5 and 137 "Redirect" (added)
    if (self._family == 4 and self._type != 0 and self._type != 5 or
        self._family == 6 and self._type != 129 and self._type != 137):
        message = f'Error type: {self._type}, code: {self._code}'
        raise ICMPError(message, self)

#
# This method is copied out the icmplib, with the `catch_messages` added to
# capture the reply messages and no longer raise on:
#  - "Type 5 — Redirect" for IPv4as
#  - "Type 137 - Redirect Message" for IPv6
#
# Both can happen and should not be handled as dropped.
#
async def async_ping2(catch_messages: List[str], address, count=4, interval=1,
         timeout=2, id=None, source=None, family=None, privileged=True,
         **kwargs):
    '''
    Send ICMP Echo Request packets to a network host.

    This function is non-blocking.

    :type address: str
    :param address: The IP address, hostname or FQDN of the host to
        which messages should be sent. For deterministic behavior,
        prefer to use an IP address.

    :type count: int, optional
    :param count: The number of ping to perform. Default to 4.

    :type interval: int or float, optional
    :param interval: The interval in seconds between sending each packet.
        Default to 1.

    :type timeout: int or float, optional
    :param timeout: The maximum waiting time for receiving a reply in
        seconds. Default to 2.

    :type id: int, optional
    :param id: The identifier of ICMP requests. Used to match the
        responses with requests. In practice, a unique identifier should
        be used for every ping process. On Linux, this identifier is
        ignored when the `privileged` parameter is disabled. The library
        handles this identifier itself by default.

    :type source: str, optional
    :param source: The IP address from which you want to send packets.
        By default, the interface is automatically chosen according to
        the specified destination.

    :type family: int, optional
    :param family: The address family if a hostname or FQDN is specified.
        Can be set to `4` for IPv4 or `6` for IPv6 addresses. By default,
        this function searches for IPv4 addresses first before searching
        for IPv6 addresses.

    :type privileged: bool, optional
    :param privileged: When this option is enabled, this library fully
        manages the exchanges and the structure of ICMP packets.
        Disable this option if you want to use this function without
        root privileges and let the kernel handle ICMP headers.
        Default to True.
        Only available on Unix systems. Ignored on Windows.

    Advanced (**kwags):

    :type payload: bytes, optional
    :param payload: The payload content in bytes. A random payload is
        used by default.

    :type payload_size: int, optional
    :param payload_size: The payload size. Ignored when the `payload`
        parameter is set. Default to 56.

    :type traffic_class: int, optional
    :param traffic_class: The traffic class of ICMP packets.
        Provides a defined level of service to packets by setting the DS
        Field (formerly TOS) or the Traffic Class field of IP headers.
        Packets are delivered with the minimum priority by default
        (Best-effort delivery).
        Intermediate routers must be able to support this feature.
        Only available on Unix systems. Ignored on Windows.

    :rtype: Host
    :returns: A `Host` object containing statistics about the desired
        destination.

    :raises NameLookupError: If you pass a hostname or FQDN in
        parameters and it does not exist or cannot be resolved.
    :raises SocketPermissionError: If the privileges are insufficient to
        create the socket.
    :raises SocketAddressError: If the source address cannot be assigned
        to the socket.
    :raises ICMPSocketError: If another error occurs. See the
        `ICMPv4Socket` or `ICMPv6Socket` class for details.

    Usage::

        >>> import asyncio
        >>> from icmplib import async_ping
        >>> host = asyncio.run(async_ping('1.1.1.1'))
        >>> host.avg_rtt
        13.2
        >>> host.is_alive
        True

    See the `Host` class for details.

    '''
    if is_hostname(address):
        address = (await async_resolve(address, family))[0]

    if is_ipv6_address(address):
        _Socket = ICMPv6Socket
    else:
        _Socket = ICMPv4Socket

    id = id or unique_identifier()
    packets_sent = 0
    rtts = []

    with AsyncSocket(_Socket(source, privileged)) as sock:
        for sequence in range(count):
            if sequence > 0:
                await asyncio.sleep(interval)

            request = ICMPRequest(
                destination=address,
                id=id,
                sequence=sequence,
                **kwargs)

            try:
                sock.send(request)
                packets_sent += 1

                reply = await sock.receive(request, timeout)

                # patched; ignore redirect and catch messages
                _raise_for_status(reply, catch_messages)

                rtt = (reply.time - request.time) * 1000
                rtts.append(rtt)

            except ICMPLibError:
                pass

    return Host(address, packets_sent, rtts)
