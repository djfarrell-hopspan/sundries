
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

    pass


class ClientRunningEvents(kldetails.KernelLoaderEvents):


    def send_ping(self, to_name):

        if b'ping' in self.events:
            self.events[b'ping'].on_send(to_name)
        else:
            loge(f'send_ping: ping not in events: {tuple(self.events.keys())}')

    def on_has_server(self, to_name):

        self.send_ping(to_name)

    def send_register_blob(self, to_name, blob_name, blob_size):

        _cmd = 'send_register_blob'
        msg = {
            b'to': to_name,
            b'blob_name': blob_name,
            b'blob_size': f'{blob_size}',
        }

        logd(f'client[{self.name}]: to[{to_name}]: {_cmd})')

        return self.send_kv(b'register_blob', msg)
