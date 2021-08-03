
from enum import Enum
import functools


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


class EnumHelper(Enum):

    @classmethod
    def values(cls):

        return set(v.value for v in cls.__members__.values())

    @classmethod
    def get(cls, name):

        return getattr(cls, name, None)
