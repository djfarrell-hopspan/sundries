
import functools
import time

from . import clientevents
from . import kldetails
from . import serverevents


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


class ClientStartupEvents(kldetails.KernelLoaderEvents):

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


class ClientRunningEvents(kldetails.KernelLoaderEvents):


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


