
import functools
import time

import eventio
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
    logd = e


class KLHandler(eventio.Handler):

    def __init__(self, subject):

        self.subject = subject
        eventio.Handler.__init__(self, self.subject.name, self.subject.so.fileno())

    def on_readable(self, fd):

        self.subject.run_one()


class ServerKLHandler(KLHandler):

    def on_run(self):

        self.subject.send_hello()


class ClientKLHandler(KLHandler):

    def __init__(self, *args, **kwargs):

        self.pingers = {}

        KLHandler.__init__(self, *args, **kwargs)

    def on_pong(self, from_name, src):

        k = (src, from_name)
        if k in self.pingers:
            self.pingers[k] = time.monotonic()

        self.poller.add_timeout(self.on_pong_timeout, 1., args=(src, from_name))

    def on_has_server(self, dst, to_name):

        self.subject.send_ping(dst, to_name)
        self.pingers[(dst, to_name)] = time.monotonic()

    def on_pong_timeout(self, when, dst, to_name):

        self.subject.send_ping(dst, to_name)


def make_kl_server_handler(name, iface):

    log(f'make server handler: {name}, {iface}')

    server = kldetails.ServerKL(name, iface)
    server_handler = ServerKLHandler(server)

    return server_handler


def make_kl_client_handler(name, iface):

    log(f'make client handler: {name}, {iface}')

    client = kldetails.ClientKL(name, iface)
    client_handler = ClientKLHandler(client)
    client.on_has_server = client_handler.on_has_server
    client.on_pong = client_handler.on_pong

    return client_handler
