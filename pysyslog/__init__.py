import asyncio
import re

MAXBUFFERSIZE = 65535
DELIMITER = bytes('\n', 'ascii')

__all__ = ['SyslogProtocol']

class SyslogProtocol(asyncio.Protocol):

    def __init__(self):
        self.recvbuffer = bytearray()
        self.delimiter = DELIMITER
        self.maxbuffersize = MAXBUFFERSIZE

    def connection_made(self, transport):
        self.remote_host = transport.get_extra_info('peername')

    def datagram_received(self, data, addr):
        self.handle_message(data, addr)

    def data_received(self, data):
        self.recvbuffer.extend(data)
        if len(self.recvbuffer) > self.maxbuffersize:
            self.overflow()
            self.recvbuffer = bytearray()
        while True:
            (event, partition, rest) = self.recvbuffer.partition(self.delimiter)
            if partition == self.delimiter:
                self.handle_message(event, self.remote_host)
                self.recvbuffer = rest
            else:
                break

    def overflow(self):
        pass

    def handle_message(self, event, sender):
        try:
            msg = event.decode('ascii')
            event = self.decode_message(msg)
            self.handle_event(event)
        except UnicodeDecodeError:
            self.decode_error("message is not 7-bit clean")

    def decode_message(self, message):
        event = {}
        syslog_re = r"<(\d{1,3})>(\w{3} [ \d]\d \d\d:\d\d:\d\d) (\w+) ([a-zA-Z0-9]{0,32}).(.*)$"
        m = re.match(syslog_re, message)
        if m is not None:
            fac, sev = self._decode_PRI(int(m.group(1)))
            event['facility'] = fac
            event['severity'] = sev
            event['timestamp'] = m.group(2)
            event['host'] = m.group(3)
            event['tag'] = m.group(4)
            event['message'] = m.group(5)
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

