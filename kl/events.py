
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

        logd(f'New event: {self.__class__.__name__}: {handler}')
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
