
import binascii
import functools
import os
import socket
import subprocess


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


def ip(*args):

    ret = True
    cmd = ['ip'] + list(args)
    log(f'running: [{" ".join(cmd)}]')
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as cpe:
        loge(f'error running: [{" ".join(cmd)}]: {cpe}')
        ret = False

    return ret


def ip_link(*args):

    return ip('link', *args)


def ip_link_set(*args):

    return ip_link('set', *args)


def ip_link_set_promisc(iface):

    return ip_link_set(iface, 'promisc', 'on')


def iface_get_mac(iface):

    path = os.path.join('/sys', 'class', 'net', iface, 'address')
    address = None
    try:
        address = open(path).read().strip().replace(':', '')
    except IOError as e:
        loge(f'error reading: {path}: {e}')
    except OSError as e:
        loge(f'error reading: {path}: {e}')
    except Exception as e:
        loge(f'error reading: {path}: {e}')

    try:
        address = binascii.a2b_hex(address)[:6]
    except binascii.Error as e:
        loge(f'error converting: {address}: {e}')
        address = None
    except Exception as e:
        loge(f'error converting: {address}: {e}')
        address = None

    return address


ETH_P_ALL = 3
def iface_make_ltwo_socket(iface):

    so = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    so.bind((iface, 0))

    return so
