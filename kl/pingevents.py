
import functools
import time

from . import events

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


class Ping(events.KLEvent):

    name = b'ping'

    def __init__(self, handler, *args):

        events.KLEvent.__init__(self, handler, *args)
        self.ponger = Pong(handler, *args)
        self.ponger.set_pinger(self)

    def on_send(self, to_name):

        msg = {
            b'time': time.monotonic(),
        }

        self.handler.send_event(self.name, to_name, msg)

    def on_received(self, from_name, msg):

        self.handler.pingers[from_name] = time.monotonic()
        self.ponger.on_send(from_name)

        return True


class Pong(events.KLEvent):

    name = b'pong'

    def __init__(self, *args):

        events.KLEvent.__init__(self, *args)
        self.pinger = None

    def set_pinger(self, pinger):

        self.pinger = pinger

    def on_send(self, to_name):

        msg = {
            b'time': time.monotonic(),
        }

        return self.handler.send_event(self.name, to_name, msg)

    def on_received(self, from_name, msg):

        self.handler.pingers[from_name] = time.monotonic()
        self.handler.poller.add_timeout(self.on_pong_timeout, 1., args=(from_name,))

        return True

    def on_pong_timeout(self, when, from_name):

        if from_name in self.handler.pingers:
            self.pinger.on_send(from_name)


def get_events(handler):

    ping = Ping(handler)
    pong = ping.ponger

    events = {
        ping,
        pong,
    }

    return events
