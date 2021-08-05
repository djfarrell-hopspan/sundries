
import functools
import time

import eventio
from . import clientevents
from . import kldetails
from . import pingevents
from . import serverevents
from . import startupevents


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


class BaseKLHandler(object):

    def __init__(self, subject):

        logw(f'BaseKLHandler.__init__: {subject}')

        self.subject = subject

        self.event_set = \
                pingevents.get_events(self) | \
                startupevents.get_events(self)

        self.events = {}
        for event in self.event_set:
            self.events[event.name] = event

    def send_event(self, name, to_name, msg):

        log(f'send_event: {name}: {to_name}: {tuple(msg.keys())}')
        msg[b'to'] = to_name

        self.subject.send_kv(name, msg)

    def handle_event(self, name, from_name, msg):

        log(f'handle_event: {name}: {from_name}: {tuple(msg.keys())}')

        ret = False
        if name in self.events:
            self.events[name].on_received(from_name, msg)
            ret = True

        return ret

class KLHandler(eventio.Handler):

    def __init__(self, subject):

        eventio.Handler.__init__(self, self.subject.name, self.subject.my_transport.so.fileno())

    def on_readable(self, fd):

        self.subject.my_transport.on_readable(fd)

    def on_check_pingers(self, when):

        now = time.monotonic()

        for k, pong_time in list(self.pingers.items()):
            if now - pong_time > 2.5:
                logw(f'on_check_pingers: removing: {k}')
                self.pingers.pop(k)

        self.poller.add_timeout(self.on_check_pingers, 0.25)

    def has_connection(self, from_name):

        return from_name in self.pingers

    def on_run(self):

        self.poller.add_timeout(self.on_check_pingers, 0.25)


class ServerKLHandler(KLHandler, BaseKLHandler, serverevents.ServerStartupEvents, serverevents.ServerRunningEvents):

    def __init__(self, subject, *args, **kwargs):

        BaseKLHandler.__init__(self, subject, *args, **kwargs)
        KLHandler.__init__(self, subject, *args, **kwargs)

    def on_run(self):

        KLHandler.on_run(self)
        self.send_hello()


class ClientEvents(clientevents.ClientStartupEvents, clientevents.ClientRunningEvents):

    def on_has_server(self, to_name):

        self.send_ping(to_name)
        self.register_blobs(to_name)
        self.pingers[to_name] = time.monotonic()

    def register_blobs(self, to_name):

        pass


class ClientKLHandler(KLHandler, BaseKLHandler, ClientEvents):

    blobs = {
        'kernel': 123456,
        'initramfs': 78901,
    }

    def __init__(self, subject, *args, **kwargs):

        BaseKLHandler.__init__(self, subject, *args, **kwargs)
        KLHandler.__init__(self, subject, *args, **kwargs)


class ClientTransportHandler(eventio.Handler, ClientEvents, BaseKLHandler):

    blobs = {
        'kernel': 123456,
        'initramfs': 78901,
    }

    def __init__(self, subject, transport, *args, **kwargs):

        BaseKLHandler.__init__(self, subject)
        self.transport = transport
        eventio.Handler.__init__(self, *args, **kwargs)

    def register_blobs(self, to_name):

        for blob_name, blob_size in self.blobs.items():

            self.send_register_blob(to_name, blob_name, blob_size)

    def on_readable(self, fd):

        return self.transport.on_readable(fd)


class ClientKLAcceptHandler(kldetails.KernelLoaderEvents, KLHandler, BaseKLHandler):

    def __init__(self, subject, *args, **kwargs):

        BaseKLHandler.__init__(self, subject)
        KLHandler.__init__(self, subject, *args, **kwargs)

        # fd -> ClientKLHandler
        self.connections = {}
        self.transport_class = self.subject.my_transport.__class__
        self.subject.my_transport.on_accept = self.on_accept
        self.on_readable = self.subject.my_transport.accept

        self.subject.my_transport.bind()
        self.subject.my_transport.listen()

    def on_accept(self, so, addr_info):

        log(f'accept handler: {addr_info}')
        transport = self.transport_class.from_accept(self.subject.name, self.subject, so, addr_info, self.subject.my_transport.to)
        transport.on_disconnect = self.on_disconnect
        handler = ClientTransportHandler(self.subject, transport, f'{addr_info}', fds=(transport.so.fileno(),))
        self.subject.add_handler(transport=transport, handler=handler)
        self.poller.add_handler(handler)

        self.connections[so.fileno()] = (transport, handler)

    def on_disconnect(self, transport):

        transport, handler = self.connections.get(transport.so.fileno())
        self.poller.pop_handler(handler)

        try:
            self.connections.pop(transport.so.fileno())
        except KeyError:
            pass

        if handler is not None:
            self.subject.on_close(transport=transport, handler=handler)

    def on_readable(self, fd):

        self.subject.my_transport.on_readable(fd)


def make_kl_server_handler(name, transport):

    log(f'make server handler: {name}, {transport}')

    server = kldetails.KernelLoader(name, transport)
    server_handler = ServerKLHandler(server)
    server_handler.add_handler(handler=server_handler)
    server.has_connection = server_handler.has_connection

    return server_handler


def make_kl_client_handler(name, transport):

    log(f'make client handler: {name}, {transport}')

    client = kldetails.KernelLoader(name, transport)

    if transport.connector and not transport.out_going:
        client_handler = ClientKLAcceptHandler(client)
    else:
        client_handler = ClientKLHandler(client)
        client_handler.add_handler(handler=client_handler)
        client.has_connection = client_handler.has_connection

    return client_handler
