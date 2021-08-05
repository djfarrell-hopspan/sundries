
import functools

from . import clientevents
from . import enumhelper
from . import events
import eventio
from . import events
from . import kldetails
from . import klevent
from . import ip
from . import pingevents
from . import serverevents
from . import startupevents
from . import transports


log =  functools.partial(print, 'info   :')
logw = functools.partial(print, 'warning:')
loge = functools.partial(print, 'error  :')
logd = functools.partial(print, 'debug  :')


def set_logfns(i, w, e, d): 

    log(f'setting log functions: {__name__}, {i}, {w}, {e}, {d}')

    modules = {
        enumhelper,
        eventio,
        kldetails,
        klevent,
        ip,
        events,
        startupevents,
        pingevents,
        serverevents,
        clientevents,
        transports,
    }

    for m in modules:
        m.set_logfns(i, w, e, d)
