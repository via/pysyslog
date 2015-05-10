import asyncio
import re

__all__ = ['SyslogProtocol']


class SyslogProtocol(asyncio.Protocol):

    delimiter = bytes('\n', 'ascii')
    maxbuffersize = 65535
    syslog_re = re.compile(r"<(\d{1,3})>(?P<timestamp>\w{3} [ \d]\d \d\d:\d\d:\d\d) " + \
                           r"(?P<host>\w+) (?P<tag>[a-zA-Z0-9]{0,32}).(?P<message>.*)$")

    def __init__(self):
        self.recvbuffer = bytearray()

    def connection_made(self, transport):
        self.remote_host = transport.get_extra_info('peername')

    def datagram_received(self, data, addr):
        self.handle_message(data, addr)

    def data_received(self, data):
        self.recvbuffer.extend(data)
        if len(self.recvbuffer) > self.maxbuffersize:
            self.overflow()
            self.recvbuffer = bytearray()

        parts = self.recvbuffer.split(self.delimiter)
        if len(parts) > 1:
            for event in parts[0:-1]:
                self.handle_message(event, self.remote_host)
            self.recvbuffer = parts[-1]

    def overflow(self):
        pass

    def handle_message(self, event, sender):
        try:
            msg = event.decode('ascii')
            event = self.decode_message(msg)
            event['sender'] = sender
            self.handle_event(event)
        except UnicodeDecodeError:
            self.decode_error("message is not 7-bit clean")

    def decode_message(self, message):
        event = {}
        m = re.match(self.syslog_re, message)
        if m is not None:
            fac, sev = self._decode_PRI(int(m.group(1)))
            event = m.groupdict()
            event['facility'] = fac
            event['severity'] = sev
        else:
            event['message'] = message
        return event

    def _decode_PRI(self, pri):
        facility = int(pri / 8)
        severity = pri % 8
        return facility, severity

    def decode_error(self, str):
        pass

    def handle_event(self, event):
        pass
