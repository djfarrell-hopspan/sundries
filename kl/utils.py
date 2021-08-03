
import functools
import os


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


def safe_remove(fname):

    try:
        os.remove(fname)
    except IOError as e:
        loge(f'error: rm: {e}')
    except OSError as e:
        loge(f'error: rm: {e}')
    except Exception as e:
        loge(f'error: rm: {e}')
