
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
    logd = d


class KLHandler(eventio.Handler):

    def __init__(self, subject):

        self.subject = subject
        self.pingers = {}

        eventio.Handler.__init__(self, self.subject.name, self.subject.so.fileno())

    def on_readable(self, fd):

        self.subject.run_one()

    def on_check_pingers(self, when):

        now = time.monotonic()

        for k, pong_time in list(self.pingers.items()):
            if now - pong_time > 1.5:
                logw(f'on_check_pingers: removing: {k}')
                self.pingers.pop(k)

        self.poller.add_timeout(self.on_check_pingers, 0.25)

    def has_connection(self, dst, from_name):

        return (dst, from_name) in self.pingers

    def on_run(self):

        self.poller.add_timeout(self.on_check_pingers, 0.25)


class ServerKLHandler(KLHandler):

    def on_run(self):

        KLHandler.on_run(self)
        self.subject.send_hello()

    def on_ping(self, from_name, src):

        k = (src, from_name)
        if k not in self.pingers:
            log(f'server handler: adding conn: {(src, from_name)}')

        self.pingers[k] = time.monotonic()


class ClientKLHandler(KLHandler):

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
    server.on_ping = server_handler.on_ping
    server.has_connection = server_handler.has_connection

    return server_handler


def make_kl_client_handler(name, iface):

    log(f'make client handler: {name}, {iface}')

    client = kldetails.ClientKL(name, iface)
    client_handler = ClientKLHandler(client)
    client.on_has_server = client_handler.on_has_server
    client.on_pong = client_handler.on_pong
    client.has_connection = client_handler.has_connection

    return client_handler
