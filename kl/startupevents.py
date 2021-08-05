
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


class Hello(events.KLEvent):

    name = b'hello'

    def __init__(self, handler, *args):

        events.KLEvent.__init__(self, handler, *args)
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


class HelloAck(events.KLEvent):

    name = b'hello_ack'

    def __init__(self, handler, *args):

        events.KLEvent.__init__(self, handler, *args)
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


class HelloDone(events.KLEvent):

    name = b'hello_done'

    def __init__(self, handler, *args):

        events.KLEvent.__init__(self, handler, *args)

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


def get_events(handler):

    hello = Hello(handler)
    hello_ack = hello.acker
    hello_done = hello_ack.doner

    events = {
        hello,
        hello_ack,
        hello_done,
    }

    return events
