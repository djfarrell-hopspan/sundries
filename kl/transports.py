
import functools
import socket
import binascii
import struct

from . import enumhelper
from . import ip


log =  functools.partial(print, 'info   :')
logw = functools.partial(print, 'warning:')
loge = functools.partial(print, 'error  :')
logd = functools.partial(print, 'debug  :')


def set_logfns(i, w, e, d): 

    global log
    global logw
    global loge
    global logd

    log = i
    logw = w
    loge = e
    logd = d


class Transport(object):

    family = None
    type_ = None
    proto = None
    connector = True

    def __init__(self, name, kl=None, so=None, addr_info=None, out_going=False, to=None):

        self.name = name
        self.addr_info = self.parse_addr_info(addr_info)
        self.other_info = None
        self.src = None
        self.dst = None
        self.so = so
        self.kl = kl
        self.out_going = out_going
        self.to = to
        self.connected = False

        if not so:
            self.make_so()
        if self.out_going:
            self.connect()
        self.so.setblocking(False)

    @classmethod
    def from_accept(cls, name, kl, so, addr_info, to):

        return cls(name, kl=kl, so=so, addr_info=addr_info, to=to)

    @classmethod
    def parse_addr_info(cls, addr_info):

        if isinstance(addr_info, tuple):
            return addr_info
        elif addr_info is None:
            return None

        first, second = addr_info.split(':')
        second = int(second)

        return (first, second)

    def set_kl(self, kl):

        self.kl = kl

    def make_so(self):

        if None not in {self.family, self.type_}:
            self.so = socket.socket(self.family, self.type_, self.proto if self.proto else -1)
            self.so.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def bind(self):

        log(f'{self}: bindinging to: {self.addr_info}')
        self.so.bind(self.addr_info)

    def connect(self):

        log(f'{self}: connecting to: {self.addr_info}')
        self.so.connect(self.addr_info)
        self.connected = True

    def listen(self):

        self.so.listen()

    def accept(self, fd):

        so, addr_info = self.so.accept()
        log(f'transport: on accept: {addr_info}')
        self.on_accept(so, addr_info)

    def on_accept(self, so, addr_info):

        log(f'transport: on accept: {addr_info}')
        so.close()

    def recv(self):

        return self.so.recv(2**16)

    def send(self, msg):

        logd(f'{self}: sending: {self.addr_info}: {msg}')
        return self.so.send(msg)

    def fileno(self):

        fd = None
        if self.so is not None:
            fd = self.so.fileno()

        return None

    def close(self):

        self.so.close()

    def on_readable(self, fd):

        if fd == self.so.fileno():
            data = self.recv()
            if not len(data):
                self.on_disconnect(self)
                self.close()
            else:
                self.on_data(data, False)
        else:
            loge(f'transport: fd mismatch: {fd} versus {self.so.fileno()}')

    def on_disconnect(self, me):

        pass

    def on_data(self, data, bcast):

        ret = None
        if data.startswith(b'type:kv '):
            ret = self.kl.recv_kv(data, bcast, transport=self)
        elif not bcast and data.startswith(b'type:blob '):
            ret = self.kl.on_blob(data)

        return ret


class Ethernet(Transport):

    family = socket.AF_PACKET
    type_ = socket.SOCK_RAW

    ETH_P_ALL = 3
    proto = socket.htons(ETH_P_ALL)
    connector = False

    etype = 0xfff1
    etype_s = struct.Struct('!H')
    etype_b = etype_s.pack(etype)
    bcast = b'\xff' * 6
    etype_len = len(etype_b)
    eaddr_len = len(bcast)
    ehdr_len = eaddr_len * 2 + etype_len

    def __init__(self, *args, **kwargs):

        kwargs['out_going'] = False
        Transport.__init__(self, *args, **kwargs)

        self.iface = self.addr_info[0]
        log(f'Ethernet: {self.iface}')
        self.addr = ip.iface_get_mac(self.iface)
        if self.addr is None:
            raise RuntimeError(f'iface[{self.iface}]: has no address')
        if not ip.ip_link_set_promisc(self.iface):
            raise RuntimeError(f'iface[{self.iface}]: could not be made promiscuous')
        log(f'address: {binascii.b2a_hex(self.addr)}')

        self.bind()
        self.src = self.bcast

    def on_epkt(self, dst, src, etype, eload):

        if etype == self.etype:
            return Transport.on_data(self, eload, dst == self.bcast)

        return None

    def on_data(self, data, bcast):

        ret = None
        pkt = data
        if len(pkt) >= self.ehdr_len:
            dst = pkt[:self.eaddr_len]
            src = pkt[self.eaddr_len:self.eaddr_len*2]
            etype = pkt[self.eaddr_len*2:self.eaddr_len*2 + 2]
            etype, = self.etype_s.unpack(etype)
            eload = pkt[self.eaddr_len*2 + 2:]

            if etype == self.etype and (dst == self.bcast or dst == self.addr) and \
                    (src != self.bcast):
                self.other_info = (dst, src)
                self.src, self.dst = self.other_info
                ret = Transport.on_data(self, eload, dst == self.bcast)

        return ret

    def send(self, data):

        pkt = self.src + self.addr + self.etype_b + data 

        return Transport.send(self, pkt)

class Sctp(Transport):

    family = socket.AF_INET
    type_ = socket.SOCK_STREAM
    proto = socket.IPPROTO_SCTP
    connector = True


class Transports(enumhelper.EnumHelper):

    Ethernet = 'Ethernet'
    Sctp = 'Sctp'


class RTransports(enumhelper.EnumHelper):

    Ethernet = Ethernet
    Sctp = Sctp
