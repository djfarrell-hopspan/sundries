
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
    logd = d


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

    pkv_cmds = {b'hello', b'hello_ack', b'hello_done'}
    core_msg = {b'type', b'mac', b'nonce', b'signature', b'name'}

    non_base64 = {b'type', b'length'}

    other_types = {
        b'type': bytes,
        b'length': hexstr_to_int,
    }

    def __init__(self, name, transport):

        # to -> temporal key
        self.tkeys_to = dict()
        self.tkeys_from = dict()
        # (from, to) -> shared key
        self.skeys = dict()

        self.name = name
        # name -> transport
        self.my_transport = transport
        self.my_transport.set_kl(self)
        self.transports = {
            b'__bcast__': self.my_transport,
        }

        self.handlers = {
        }

        self.pingers = {}

    def add_handler(self, transport=None, handler=None):

        if handler is None:
            return
        if transport is None:
            transport = self.my_transport
        self.handlers[transport] = handler

    @property
    def to(self):

        return self.my_transport.to

    @property
    def is_bcaster(self):

        return not self.my_transport.connector

    @property
    def is_connected(self):

        return self.my_transport.connected

    def on_close(self, handler=None, transport=None):

        logw(f'kl: closing: {handler}: {transport}')

        for name, transport_ in list(self.transports.items()):
            if transport_ is transport:
                self.transports.pop(name)
            try:
                self.pingers.pop(name)
            except KeyError:
                pass

        try:
            self.handlers.pop(handler)
        except KeyError:
            pass

    def send_kv(self, cmd, tmsg):

        to_name = tmsg.get('to')
        if to_name is None:
            to_name = tmsg.get(b'to')

        if isinstance(to_name, str):
            to_name = to_name.encode()

        if to_name is None:
            loge(f'send_kv: send_kv: no "to"')
        else:
            log(f'send_kv: sending to: {to_name}')

        transport = None
        if to_name in self.transports:
            transport = self.transports.get(to_name)
        elif self.is_connected:
            transport = self.my_transport
        elif self.is_bcaster:
            transport = self.my_transport
        else:
            logw(f'send_kv: no transport: {to_name}')
            return None

        if isinstance(cmd, str):
            cmd = cmd.encode()

        bmsg = dict()
        bmsg[b'addr_info'] = f'{self.my_transport.other_info}'.encode()
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
            try:
                base64 = binascii.b2a_base64(v, newline=False)
            except TypeError as e:
                log(f'send_kv: encoding: {k}, {v}')

            parts.append(k + b':' + base64)

        s = b' '.join(parts)

        length_len = len(' lenght:1234')
        s += b' length:' + int_to_hexstr(len(s) + length_len)
            
        logd(f'send_kv: {self.name}: {s}')
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

        log(f'send_kv: {self.name}: {s}')

        return transport.send(s)

    def on_cmd_null(self, from_name, cmd, msg):

        log(f'{self.name}: {from_name}: null: cmd: {msg}')

        return None

    def recv_kv(self, data, bcast, transport=None):

        logd(f'recv_kv: data: {data}')
        split = data.split(b' ')
        signature = split[-1]
        payload = b' '.join(split[:-1])

        kvs = dict()
        logd(f'recv_kv: split: {split}')
        for part in split:
            k, v = part.split(b':')
            kvs[k] = v

        length_ok = False
        length = kvs.get(b'length')
        if length is not None:
            length = hexstr_to_int(length)
            calc_length = length + 1 + len(signature) 
            length_ok = length + 1 + len(signature) == len(data)
            if not length_ok:
                loge(f'recv_kv: bad length: {calc_length} versus {len(data)}')
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
                verified = pki.verify(name.decode(), signature, payload)
                log(f'recv_kv: verified: {verified}')
            elif signature.startswith(b'hmac:'):
                skey = self.get_skey(name)
                verified = False
                if skey is not None:
                    signature = signature.split(b':')[-1]
                    signature = decode_base64(signature)
                    logd(f'recv_kv: hmac: {signature}')
                    verified = pki.verify_hmac(skey, payload, signature)
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

        if name not in self.transports and transport is not None:
            logw(f'recv_kv: adding transport: {name}: {transport}: {transport.addr_info}')
            self.transports[name] = transport

        handler_obj = self.handlers.get(transport)
        cmd = omsg.get(b'cmd')
        logd(f'recv_kv: cmd: {cmd}: handler: {handler_obj}')
        if isinstance(cmd, bytes):
            cmd = cmd.decode()
            name = name.decode()
            handler = getattr(handler_obj, f'on_cmd_{cmd}', self.on_cmd_null)
            return handler(name, cmd, omsg)

        return None

    def on_readable(self, fd):

        return self.transport.on_readable(fd)

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

    def has_connection(self, from_name):

        return False


class KernelLoaderEvents(object):

    def __getattr__(self, name):

        if hasattr(self.subject, name):
            return getattr(self.subject, name)

        raise AttributeError(f'KernelLoader: {name}')


class ClientStartupEvents(KernelLoaderEvents):

    def on_cmd_hello(self, from_name, cmd, msg):

        _cmd = 'on_cmd_hello'
        log(f'client[{self.name}]: cmd_hello: from[{from_name}]')
        self.remove_keys(from_name)
        temporal_pkey = self.setup_tkey(from_name)
        if temporal_pkey is None:
            loge(f'client[{self.name}]: from[{from_name}]: {_cmd}: no temporal pkey') 
            return None
        else:
            log(f'client[{self.name}]: from[{from_name}]: {_cmd}: temporal pkey: {temporal_pkey}') 

        return self.send_hello_ack(from_name, temporal_pkey)

    def on_cmd_hello_done(self, from_name, cmd, msg):

        _cmd = 'on_cmd_hello_done'
        log(f'client[{self.name}]: {_cmd}: from[{from_name}]')

        temporal_pkey_from = msg.get(b'tkey')
        if temporal_pkey_from is None:
            loge(f'client[{self.name}]: from[{from_name}]: {_cmd}: no temporal pkey in msg') 
            return None
        else:
            log(f'client[{self.name}]: from[{from_name}]: {_cmd}: temporal pkey: {temporal_pkey_from}') 
            self.save_from_tkey(from_name, temporal_pkey_from)

        self.on_has_server(from_name)

        return None

    def send_hello_ack(self, to_name, tkey):

        _cmd = 'send_hello_ack'
        msg = {
            b'to': to_name,
            b'tkey': tkey,
        }

        logd(f'client[{self.name}]: to[{to_name}]: {_cmd}: to temporal pkey: {tkey}') 
        log(f'client[{self.name}]: to[{to_name}]: {_cmd}') 

        return self.send_kv(b'hello_ack', msg)


class ClientRunningEvents(KernelLoaderEvents):


    def send_ping(self, to_name):

        _cmd = 'send_ping'
        msg = {
            b'to': to_name,
            b'time': f'{time.time()}'.encode(),
        }

        logd(f'client[{self.name}]: to[{to_name}]: {_cmd})')

        return self.send_kv(b'ping', msg)

    def on_cmd_pong(self, from_name, cmd, msg):

        _cmd = 'on_cmd_pong'
        log(f'client[{self.name}]: {_cmd}: from[{from_name}]')

        self.on_pong(from_name)

        return None

    def on_pong(self, from_name):

        _cmd = 'on_pong'
        log(f'client[{self.name}]: {_cmd}: from[{from_name}]')

        return None

    def on_has_server(self, to_name):

        self.send_ping(to_name)


class ServerRunningEvents(KernelLoaderEvents):

    def on_cmd_ping(self, from_name, cmd, msg):

        _cmd = 'on_cmd_ping'
        log(f'server[{self.name}]: {_cmd}: from[{from_name}]')

        self.on_ping(from_name)
        self.send_pong(from_name)

    def on_ping(self, from_name):

        pass

    def send_pong(self, to_name):

        _cmd = 'send_pong'
        msg = {
            b'to': to_name,
            b'time': f'{time.time()}'.encode(),
        }

        logd(f'client[{self.name}]: to[{to_name}]: {_cmd})')

        return self.send_kv(b'pong', msg)


class ServerStartupEvents(KernelLoaderEvents):

    def send_hello(self):

        msg = {
            b'to': self.to,
        }

        self.send_kv(b'hello', msg)

        return None

    def send_hello_done(self, to_name):

        _cmd = 'send_hello_done'
        tkey = self.get_tkey(to_name)

        if tkey is None:
            return None

        msg = {
            b'to': to_name,
            b'tkey': tkey,
        }

        self.send_kv(b'hello_done', msg)

        return None

    def on_cmd_hello_ack(self, from_name, cmd, msg):

        _cmd = 'on_cmd_hello_ack'
        log(f'server[{self.name}]: {_cmd}: from[{from_name}]')
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

        self.send_hello_done(from_name)

        return None
