
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

    def on_cmd_register_blob(self, from_name, cmd, msg):

        _cmd = 'on_cmd_register_blob'
        log(f'server[{self.name}]: {_cmd}: from[{from_name}]')

        blob_name = msg.get(b'blob_name')
        blob_size = msg.get(b'blob_size')

        logw(f'new blob: name: {blob_name}, size: {blob_size}')


class ServerStartupEvents(kldetails.KernelLoaderEvents):

    def send_hello(self):

        logd(f'server startup: send_hello')
        helloer = self.events.get(b'hello')
        if helloer:
            log(f'{self.name}: sending hello: {self.to}')
            helloer.on_send(self.to)
        else:
            loge(f'{self.name}: no helloer')
