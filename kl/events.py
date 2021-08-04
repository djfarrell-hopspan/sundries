
import functools
import time


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


class KLEvent(object):

    name = None

    def __init__(self, handler):

        logd(f'New event: {self.__class__}: {handler}')
        self.handler = handler

    @property
    def addr_info(self):

        addr_info = None
        try:
            addr_info = self.handler.transport.addr_info
        except AttributeError:
            try:
                addr_info = self.handler.my_transport.addr_info
            except AttributeError:
                pass

        return addr_info

    def on_send(self, to_name, *args, **kwargs):

        pass

    def on_received(self, from_name, msg):

        pass


class Ping(KLEvent):

    name = b'ping'

    def __init__(self, handler, *args):

        KLEvent.__init__(self, handler, *args)
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


class Pong(KLEvent):

    name = b'pong'

    def __init__(self, *args):

        KLEvent.__init__(self, *args)
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


class Hello(KLEvent):

    name = b'hello'

    def __init__(self, handler, *args):

        KLEvent.__init__(self, handler, *args)
        self.acker = HelloAck(handler, *args)

    def on_send(self, to_name):

        self.handler.remove_keys(to_name)

        temporal_pkey = self.handler.setup_tkey(to_name)
        if temporal_pkey is None:
            loge(f'[{self.addr_info}]: {to_name}: {self.name}: no temporal pkey') 
            return False
        else:
            log(f'[{self.addr_info}]: {to_name}: {self.name}: temporal pkey: {temporal_pkey}') 

        msg = {
            b'tkey': temporal_pkey,
        }

        return self.handler.send_event(self.name, to_name, msg)

    def on_received(self, from_name, msg):

        self.handler.remove_keys(from_name)

        temporal_pkey_from = msg.get(b'tkey')
        if temporal_pkey_from is None:
            loge(f'[{self.addr_info}]: from[{from_name}]: {self.name}: no temporal pkey in msg')
        else:
            logd(f'[{self.addr_info}]: from[{from_name}]: {self.name}: temporal pkey: {temporal_pkey_from}')
            temporal_pkey = self.handler.setup_tkey(from_name)
            have_skey = self.handler.save_from_tkey(from_name, temporal_pkey_from)
            if temporal_pkey is None or not have_skey:
                loge(f'[{self.addr_info}]: from[{from_name}]: {self.name}: no temporal pkey') 
            else:
                log(f'[{self.addr_info}]: from[{from_name}]: {self.name}: temporal pkey: {temporal_pkey}') 
                self.acker.on_send(from_name, temporal_pkey)


        return True


class HelloAck(KLEvent):

    name = b'hello_ack'

    def __init__(self, handler, *args):

        KLEvent.__init__(self, handler, *args)
        self.doner = HelloDone(handler, *args)

    def on_send(self, to_name, tkey):

        msg = {
            b'tkey': tkey,
        }

        logd(f'[{self.addr_info}]: to[{to_name}]: {self.name}: to temporal pkey: {tkey}') 
        log(f'[{self.addr_info}]: to[{to_name}]: {self.name}') 

        return self.handler.send_event(self.name, to_name, msg)

    def on_received(self, from_name, msg):

        log(f'server[{self.name}]: {self.name}: from[{from_name}]')
        self.handler.remove_keys(from_name)

        temporal_pkey_from = msg.get(b'tkey')
        if temporal_pkey_from is None:
            loge(f'[{self.addr_info}]: from[{from_name}]: {self.name}: no temporal pkey in msg')
        else:
            logd(f'[{self.addr_info}]: from[{from_name}]: {self.name}: temporal pkey: {temporal_pkey_from}')
            if self.handler.save_from_tkey(from_name, temporal_pkey_from):
                self.doner.on_send(from_name, True)

        return True


class HelloDone(KLEvent):

    name = b'hello_done'

    def __init__(self, handler, *args):

        KLEvent.__init__(self, handler, *args)

    def on_send(self, to_name, success):

        msg = {
                b'success': f'{success}',
        }

        log(f'[{self.addr_info}]: to[{to_name}]: {self.name}: {success}') 

        return self.handler.send_event(self.name, to_name, msg)

    def on_received(self, from_name, msg):

        log(f'[{self.addr_info}]: {self.name}: from[{from_name}]')

        success_from = msg.get(b'success')
        if success_from is None:
            loge(f'[{self.addr_info}]: from[{from_name}]: {self.name}: no success') 
        else:
            success_from = success_from == b'True'
            log(f'[{self.addr_info}]: from[{from_name}]: {self.name}: {success_from}') 
            if success_from:
                self.handler.on_has_server(from_name)

        return True
