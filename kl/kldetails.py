
import binascii
from enum import Enum
import functools
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile
import time

from . import enumhelper
import eventio
from . import ip
from . import pki
from . import utils


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
    logd = e


def urandom(num_bytes):

    return open('/dev/urandom', 'rb').read(num_bytes)
class Modes(enumhelper.EnumHelper):

    Server = 'server'
    Client = 'client'


def decode_base64(data):

    ret = None
    try:
        ret = binascii.a2b_base64(data)
    except binascii.Error as e:
        loge(f'error: base64 decode: {e}: {data}')
    except Exception as e:
        loge(f'error: base64 decode: {e}: {data}')

    return ret


def hexstr_to_int(s):

    ret = -1
    try:
        ret = int(s, 16)
    except ValueError as e:
        loge(f'hexstr_to_int: {e}: {s}')
    except Exception as e:
        loge(f'hexstr_to_int: {e}: {s}')

    return ret



def int_to_hexstr(num):

    return f'{num:04x}'.encode()


class KernelLoader(object):

    etype = 0xfff1
    etype_s = struct.Struct('!H')
    etype_b = etype_s.pack(etype)
    bcast = b'\xff' * 6
    etype_len = len(etype_b)
    eaddr_len = len(bcast)
    ehdr_len = eaddr_len * 2 + etype_len
    pkv_cmds = {b'hello', b'hello_ack', b'hello_done'}
    core_msg = {b'type', b'mac', b'nonce', b'signature', b'name'}

    non_base64 = {b'type', b'length'}

    other_types = {
        b'type': bytes,
        b'length': hexstr_to_int,
    }

    def __init__(self, name, iface):

        # to -> temporal key
        self.tkeys_to = dict()
        self.tkeys_from = dict()
        # (from, to) -> shared key
        self.skeys = dict()

        self.name = name
        self.iface = iface
        self.addr = ip.iface_get_mac(iface)
        if self.addr is None:
            raise RuntimeError(f'iface[{iface}]: as no address')
        if not ip.ip_link_set_promisc(iface):
            raise RuntimeError(f'iface[{iface}]: could not be made promiscuous')
        log(f'address: {binascii.b2a_hex(self.addr)}')
        self.so = ip.iface_make_ltwo_socket(iface)

    def send(self, dst, data):

        pkt = dst + self.addr + self.etype_b + data

        return self.so.send(pkt)

    def send_kv(self, dst, cmd, tmsg):

        if isinstance(cmd, str):
            cmd = cmd.encode()

        bmsg = dict()
        bmsg[b'mac'] = self.addr
        bmsg[b'nonce'] = urandom(12)
        bmsg[b'name'] = self.name.encode()
        bmsg[b'cmd'] = cmd
        log(f'send_kv: cmd: {cmd}')

        for k, v in tmsg.items():
            if isinstance(k, str):
                k = k.encode(k)
            if k not in bmsg and k not in self.core_msg and k != 'signature':
                if isinstance(v, str):
                    v = v.encode()
                bmsg[k] = v

        to = None
        hsign = False
        if b'to' in bmsg:
            to = bmsg[b'to']
            hmac_key = self.get_skey(to.decode())
            if hmac_key is not None:
                logd(f'send_kv: hmac_key: {hmac_key}')
                hsign = True
            else:
                loge(f'send_kv: no "skey": {to.decode()}')
        else:
            loge(f'send_kv: no "to"')

        psign = cmd in self.pkv_cmds

        have_sign = hsign or psign
        one_sign = hsign ^ psign

        if not have_sign:
            logd(f'send_kv: no sign method')
            return None
        if not one_sign:
            logd(f'send_kv: two sign methods')

        parts = []
        parts.append(b'type:kv')
        for k, v in bmsg.items():
            base64 = binascii.b2a_base64(v, newline=False)
            parts.append(k + b':' + base64)

        s = b' '.join(parts)

        length_len = len(' lenght:1234')
        s += b' length:' + int_to_hexstr(len(s) + length_len)
            
        logd(f'send_kv: {self.name}: to[{dst}]: {s}')
        signature_slug = b''
        if psign:
            signature_slug = b' signature:'
            signature = pki.sign(self.name, s)
        elif hsign:
            signature = pki.calc_hmac(hmac_key, s)
            signature_slug = b' hmac:'
        else:
            return None

        s += signature_slug + binascii.b2a_base64(signature, newline=False)

        log(f'send_kv: {self.name}: to[{dst}]: {s}')

        return self.send(self.bcast, s)

    def cast_kv(self, cmd, tmsg):

        log(f'cast_kv: msg: {cmd}: {tmsg}')

        return self.send_kv(self.bcast, cmd, tmsg)

    def on_cmd_null(self, from_name, src, cmd, msg):

        log(f'{self.name}: from {src}: null: cmd: {msg}')

        return None

    def recv_kv(self, src, eload):

        logd(f'recv_kv: eload: {eload}')
        split = eload.split(b' ')
        signature = split[-1]
        data = b' '.join(split[:-1])

        kvs = dict()
        logd(f'recv_kv: split: {split}')
        for part in split:
            k, v = part.split(b':')
            kvs[k] = v

        length_ok = False
        length = kvs.get(b'length')
        if length is not None:
            length = hexstr_to_int(length)
            length_ok = length + 1 + len(signature) == len(eload)
            if not length_ok:
                loge(f'recv_kv: bad length: {length} versus {len(data)}')
        else:
            loge(f'recv_kv: no length')

        verified = False
        name = kvs.get(b'name')
        logd(f'recv_kv: name: {name}')
        if name is not None and length_ok:
            name = decode_base64(name)
            if signature.startswith(b'signature:'):
                signature = signature.split(b':')[-1]
                signature = decode_base64(signature)
                logd(f'recv_kv: signature: {signature}')
                verified = pki.verify(name.decode(), signature, data)
                log(f'recv_kv: verified: {verified}')
            elif signature.startswith(b'hmac:'):
                skey = self.get_skey(name)
                verified = False
                if skey is not None:
                    signature = signature.split(b':')[-1]
                    signature = decode_base64(signature)
                    logd(f'recv_kv: hmac: {signature}')
                    verified = pki.verify_hmac(skey, data, signature)
                log(f'recv_kv: hmac verified: {verified}')
        else:
            logd(f'recv_kv: sig: {signature}')
            signature = None

        omsg = dict()
        cmsg = dict()
        if verified:
            for k, v in kvs.items():
                if k not in self.non_base64:
                    v = decode_base64(v)
                    if v and k not in self.core_msg:
                        omsg[k] = v
                    elif v:
                        cmsg[k] = v
                    else:
                        log(f'recv_kv: bad v: {v}')

            if set(cmsg.keys()) - self.core_msg:
                logw(f'recv_kv: not all core msg: {set(cmsg.keys())}')
                omsg = dict()
            elif cmsg[b'mac'] != src:
                logw(f'recv_kv: src mismatch: msg[{cmsg[b"mac"]}] vs pkt[{src}]')
                omsg = dict()

        cmd = omsg.get(b'cmd')
        logd(f'recv_kv: cmd: {cmd}')
        if isinstance(cmd, bytes):
            cmd = cmd.decode()
            name = name.decode()
            handler = getattr(self, f'on_cmd_{cmd}', self.on_cmd_null)
            return handler(name, src, cmd, omsg)

        return None

    def on_ekl_bcast_kv(self, src, eload):

        return self.recv_kv(src, eload)

    def on_ekl_bcast(self, src, eload):

        logd(f'server: ekl_bcast: {src}: {eload}')

        if eload.startswith(b'type:kv '):

            return self.on_ekl_bcast_kv(src, eload)

        return None

    def on_ekl(self, dst, src, eload):

        if dst == self.bcast:

            return self.on_ekl_bcast(src, eload)

        return None

    def on_epkt(self, dst, src, etype, eload):

        if etype == self.etype:

            return self.on_ekl(dst, src, eload)

        return None

    def run_one(self):

        pkt = self.so.recv(2**16)
        logd(f'recv pkt: len={len(pkt)}')
        if len(pkt) >= self.ehdr_len:
            dst = pkt[:self.eaddr_len]
            src = pkt[self.eaddr_len:self.eaddr_len*2]
            etype = pkt[self.eaddr_len*2:self.eaddr_len*2 + 2]
            etype, = self.etype_s.unpack(etype)
            eload = pkt[self.eaddr_len*2 + 2:]

            return self.on_epkt(dst, src, etype, eload)

        return None

    def idle(self):

        while True:

            self.run_one()

    def setup_tkey(self, to_name):

        _cmd = 'setup_tkey'
        temporal_pkey = pki.make_temporal_me_to_them(self.name, to_name)
        if temporal_pkey is None:
            logw(f'client[{self.name}]: {_cmd}: no temporal pkey') 
            return None
        else:
            log(f'client[{self.name}]: {_cmd}: temporal pkey: {temporal_pkey}') 
            self.tkeys_to[to_name] = temporal_pkey

        return temporal_pkey

    def get_tkey(self, to_name):

        _cmd = 'get_tkey'
        temporal_pkey = self.tkeys_to.get(to_name)
        if temporal_pkey is None:
            logw(f'client[{self.name}]: {_cmd}: no temporal pkey') 
        else:
            log(f'client[{self.name}]: {_cmd}: temporal pkey: {temporal_pkey}') 

        return temporal_pkey

    def get_skey(self, to_name):

        _cmd = 'get_skey'
        if isinstance(to_name, bytes):
            to_name = to_name.decode()

        skey = self.skeys.get(to_name)
        if skey is None:
            logw(f'client[{self.name}]: {_cmd}: no skey') 
        else:
            logd(f'client[{self.name}]: {_cmd}: skey: {skey}') 

        return skey

    def save_from_tkey(self, from_name, temporal_pkey_from):

        tkey_fname = f'{from_name}_{self.name}_public.pem'
        with open(tkey_fname, 'wb') as outf:
            if isinstance(temporal_pkey_from, str):
                temporal_pkey_from = temporal_pkey_from.encode()

            outf.write(temporal_pkey_from)
            outf.flush()
            self.tkeys_from[from_name] = temporal_pkey_from
            skey = pki.derive_temporal_key(from_name, self.name)
            if skey is None:
                logw(f'save_from_tkey: no skey')
                self.tkeys_from.pop(from_name)
            else:
                logd(f'save_from_tkey: skey: {skey}')
                self.skeys[from_name] = skey

    def remove_keys(self, from_name):

        log(f'remove_keys...')
        try:
            self.skeys.pop(from_name)
        except KeyError:
            pass

        try:
            self.tkeys_to.pop(from_name)
        except KeyError:
            pass

        try:
            self.tkeys_from.pop(from_name)
        except KeyError:
            pass

class ClientKL(KernelLoader):

    def on_cmd_hello(self, from_name, src, cmd, msg):

        _cmd = 'on_cmd_hello'
        log(f'client[{self.name}]: cmd_hello: from[{from_name}--{src}]')
        self.remove_keys(from_name)
        temporal_pkey = self.setup_tkey(from_name)
        if temporal_pkey is None:
            loge(f'client[{self.name}]: from[{from_name}]: {_cmd}: no temporal pkey') 
            return None
        else:
            log(f'client[{self.name}]: from[{from_name}]: {_cmd}: temporal pkey: {temporal_pkey}') 

        return self.send_hello_ack(src, from_name, temporal_pkey)

    def on_cmd_hello_done(self, from_name, src, cmd, msg):

        _cmd = 'on_cmd_hello_done'
        log(f'client[{self.name}]: {_cmd}: from[{from_name}]')

        temporal_pkey_from = msg.get(b'tkey')
        if temporal_pkey_from is None:
            loge(f'client[{self.name}]: from[{from_name}]: {_cmd}: no temporal pkey in msg') 
            return None
        else:
            log(f'client[{self.name}]: from[{from_name}]: {_cmd}: temporal pkey: {temporal_pkey_from}') 
            self.save_from_tkey(from_name, temporal_pkey_from)

        self.on_has_server(src, from_name)

        return None

    def send_ping(self, dst, to_name):

        _cmd = 'send_ping'
        msg = {
            b'to': to_name,
            b'time': f'{time.time()}'.encode(),
        }

        logd(f'client[{self.name}]: to[{to_name}]: {_cmd})')

        return self.send_kv(dst, b'ping', msg)

    def on_cmd_pong(self, from_name, src, cmd, msg):

        _cmd = 'on_cmd_pong'
        log(f'server[{self.name}]: {_cmd}: from[{from_name}--{src}]')

        self.on_pong(from_name, src)

        return None

    def on_pong(self, from_name, src):

        _cmd = 'on_pong'
        log(f'server[{self.name}]: {_cmd}: from[{from_name}--{src}]')

        return None

    def send_hello_ack(self, dst, to_name, tkey):

        _cmd = 'send_hello_ack'
        msg = {
            b'to': to_name,
            b'tkey': tkey,
        }

        logd(f'client[{self.name}]: to[{to_name}]: {_cmd}: to temporal pkey: {tkey}') 
        log(f'client[{self.name}]: to[{to_name}]: {_cmd}') 

        return self.send_kv(dst, b'hello_ack', msg)

    def on_has_server(self, dst, to_name):

        self.send_ping(dst, to_name)


class ServerKL(KernelLoader):

    def on_cmd_ping(self, from_name, src, cmd, msg):

        _cmd = 'on_cmd_ping'
        log(f'server[{self.name}]: {_cmd}: from[{from_name}--{src}]')

        self.send_pong(src, from_name)

    def send_pong(self, dst, to_name):

        _cmd = 'send_pong'
        msg = {
            b'to': to_name,
            b'time': f'{time.time()}'.encode(),
        }

        logd(f'client[{self.name}]: to[{to_name}]: {_cmd})')

        return self.send_kv(dst, b'pong', msg)

    def send_hello(self):

        msg = dict()

        self.cast_kv(b'hello', msg)

        return None

    def send_hello_done(self, dst, to_name):

        _cmd = 'send_hello_done'
        tkey = self.get_tkey(to_name)

        if tkey is None:
            return None

        msg = {
            b'to': to_name,
            b'tkey': tkey,
        }

        self.send_kv(dst, b'hello_done', msg)

        return None

    def on_cmd_hello_ack(self, from_name, src, cmd, msg):

        _cmd = 'on_cmd_hello_ack'
        log(f'server[{self.name}]: {_cmd}: from[{from_name}--{src}]')
        self.remove_keys(from_name)

        temporal_pkey = self.setup_tkey(from_name)
        if temporal_pkey is None:
            loge(f'client[{self.name}]: from[{from_name}]: {_cmd}: no temporal pkey') 
            return None
        else:
            logd(f'client[{self.name}]: from[{from_name}]: {_cmd}: temporal pkey: {temporal_pkey}') 

        temporal_pkey_from = msg.get(b'tkey')
        if temporal_pkey_from is None:
            loge(f'client[{self.name}]: from[{from_name}]: {_cmd}: no temporal pkey in msg') 
            return None
        else:
            logd(f'client[{self.name}]: from[{from_name}]: {_cmd}: temporal pkey: {temporal_pkey_from}') 
            self.save_from_tkey(from_name, temporal_pkey_from)

        self.send_hello_done(src, from_name)

        return None
