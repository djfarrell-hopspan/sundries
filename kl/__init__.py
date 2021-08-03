
import functools

from . import enumhelper
import eventio
from . import kldetails
from . import klevent
from . import ip
from . import transports


log =  functools.partial(print, 'info   :')
logw = functools.partial(print, 'warning:')
loge = functools.partial(print, 'error  :')
logd = functools.partial(print, 'debug  :')


def set_logfns(i, w, e, d): 

    log('setting log functions: {__name__}, {i}, {w}, {e}, {d}')

    enumhelper.set_logfns(i, w, e, d)
    eventio.set_logfns(i, w, e, d)
    kldetails.set_logfns(i, w, e, d)
    klevent.set_logfns(i, w, e, d)
    ip.set_logfns(i, w, e, d)
    transports.set_logfns(i, w, e, d)
