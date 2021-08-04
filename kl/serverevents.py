
import functools
import time

from . import kldetails


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


class ServerRunningEvents(kldetails.KernelLoaderEvents):

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


class ServerStartupEvents(kldetails.KernelLoaderEvents):

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
