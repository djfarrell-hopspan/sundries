
import functools
import socket
import binascii
import struct

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

    def __init__(self, name, connect_info=None, bind_info=None):

        self.name = name
        self.bind_info = bind_info
        self.connect_info = connect_info
        self.other_info = None
        self.src = None
        self.dst = None
        self.so = None
        self.kl = None

        self.make_so()

    def set_kl(self, kl):

        self.kl = kl

    def make_so(self):

        if None not in {self.family, self.type_}:
            self.so = socket.socket(self.family, self.type_, self.proto if self.proto else -1)
            self.so.setblocking(False)

    def bind(self):

        self.so.bind(self.bind_info)

    def connect(self):

        self.so.connect(self.connect_info)

    def listen(self):

        self.so.listen()

    def accept(self):

        new_addr_info = self.so.accept()
        self.on_accept(new_addr_info)

    def on_accept(self, addr_info):

        log(f'transport: on accept: {addr_info}')

    def recv(self):

        return self.so.recv(2**16)

    def send(self, msg):

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
                self.on_disconnect()
                self.close()
            else:
                self.on_data(data, False)
        else:
            loge(f'transport: fd mismatch: {fd} versus {self.so.fileno()}')

    def on_data(self, data, bcast):

        ret = None
        if data.startswith(b'type:kv '):
            ret = self.kl.recv_kv(data, bcast)
        elif not bcast and data.startswith(b'type:blob '):
            ret = self.kl.on_blob(data)

        return ret


class Ethernet(Transport):

    family = socket.AF_PACKET
    type_ = socket.SOCK_RAW

    ETH_P_ALL = 3
    proto = socket.htons(ETH_P_ALL)

    etype = 0xfff1
    etype_s = struct.Struct('!H')
    etype_b = etype_s.pack(etype)
    bcast = b'\xff' * 6
    etype_len = len(etype_b)
    eaddr_len = len(bcast)
    ehdr_len = eaddr_len * 2 + etype_len

    def __init__(self, iface, *args, **kwargs):

        log(f'Ethernet: {iface}')
        self.iface = iface
        self.addr = ip.iface_get_mac(iface)
        if self.addr is None:
            raise RuntimeError(f'iface[{iface}]: has no address')
        if not ip.ip_link_set_promisc(iface):
            raise RuntimeError(f'iface[{iface}]: could not be made promiscuous')
        log(f'address: {binascii.b2a_hex(self.addr)}')

        Transport.__init__(self, *args, bind_info=(iface, 0))
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
    type_ = socket.SOCK_SEQPACKET
