
import binascii
from enum import Enum
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile


def urandom(num_bytes):

    return open('/dev/urandom', 'rb').read(num_bytes)


def ip(*args):

    ret = True
    cmd = ['ip'] + list(args)
    log(f'running: [{" ".join(cmd)}]')
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as cpe:
        log(f'error running: [{" ".join(cmd)}]: {cpe}')
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
        log(f'error reading: {path}: {e}')
    except OSError as e:
        log(f'error reading: {path}: {e}')
    except Exception as e:
        log(f'error reading: {path}: {e}')

    try:
        address = binascii.a2b_hex(address)[:6]
    except binascii.Error as e:
        log(f'error converting: {address}: {e}')
        address = None
    except Exception as e:
        log(f'error converting: {address}: {e}')
        address = None

    return address


ETH_P_ALL = 3
def iface_make_ltwo_socket(iface):

    so = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    so.bind((iface, 0))

    return so


class EnumHelper(Enum):

    @classmethod
    def values(cls):

        return set(v.value for v in cls.__members__.values())

    @classmethod
    def get(cls, name):

        return getattr(cls, name, None)


class Modes(EnumHelper):

    Server = 'server'
    Client = 'client'


def openssl_sign(name, data):

    signature = None
    if isinstance(data, str):
        data = data.encode()

    try:
        with subprocess.Popen(['openssl', 'dgst', '-sha256', '-sign', f'{name}private.pem'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as signer:
            signer.stdin.write(data)
            signer.stdin.close()
            signature = signer.stdout.read()
            signer.wait(timeout=1.)
    except Subprocess.TimeoutExpired as e:
        log(f'error error: {e}')
    except Exception as e:
        log(f'signer error: {e}')

    return signature


def openssl_verify(name, signature, data):

    verified = False
    if isinstance(data, str):
        data = data.encode()

    verifier_out = '(none)'
    with tempfile.NamedTemporaryFile(mode='wb', buffering=0) as sig_file:
        try:
            sig_file.write(signature)
            sig_file.seek(0)
        except Exception as e:
            log(f'tempfile error: {e}')
        try:
            with subprocess.Popen(['openssl', 'dgst', '-sha256', '-verify', f'{name}public.pem', '-binary', '-signature', f'{sig_file.name}'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as verifier:
                verifier.stdin.write(data)
                verifier.stdin.close()
                verifier_out = verifier.stdout.read()
                verifier.wait(timeout=1.)
                verified = verifier.returncode == 0
        except Subprocess.TimeoutExpired as e:
            log(f'verifier error: {e}: {verifier_out}')
        except Exception as e:
            log(f'verifier error: {e}: {verifier_out}')

    return verified


def decode_base64(data):

    ret = None
    try:
        ret = binascii.a2b_base64(data)
    except binascii.Error as e:
        log(f'error: base64 decode: {e}: {data}')
    except Exception as e:
        log(f'error: base64 decode: {e}: {data}')

    return ret

class KernelLoader(object):

    etype = 0xfff1
    etype_s = struct.Struct('!H')
    etype_b = etype_s.pack(etype)
    bcast = b'\xff' * 6
    etype_len = len(etype_b)
    eaddr_len = len(bcast)
    ehdr_len = eaddr_len * 2 + etype_len
    core_msg = {b'type', b'mac', b'nonce', b'signature', b'name'}

    def __init__(self, name, iface):

        self.name = name
        self.iface = iface
        self.addr = iface_get_mac(iface)
        if self.addr is None:
            raise RuntimeError(f'iface[{iface}]: as no address')
        if not ip_link_set_promisc(iface):
            raise RuntimeError(f'iface[{iface}]: could not be made promiscuous')
        log(f'address: {binascii.b2a_hex(self.addr)}')
        self.so = iface_make_ltwo_socket(iface)

    def send(self, dst, data):

        pkt = dst + self.addr + self.etype_b + data

        return self.so.send(pkt)

    def send_kv(self, dst, tmsg):

        bmsg = dict()
        bmsg[b'mac'] = self.addr
        bmsg[b'nonce'] = urandom(12)
        bmsg[b'name'] = self.name.encode()

        for k, v in tmsg.items():
            if k not in bmsg and k not in self.core_msg and k != 'signature':
                if isinstance(v, str):
                    v = v.encode()
                bmsg[k.encode()] = v

        parts = []
        parts.append(b'type:kv')
        for k, v in bmsg.items():
            base64 = binascii.b2a_base64(v, newline=False)
            parts.append(k + b':' + base64)

        s = b' '.join(parts)
        log(f'send_kv: {self.name}: to[{dst}]: {s}')
        signature = openssl_sign(self.name, s)
        s += b' signature:' + binascii.b2a_base64(signature, newline=False)

        log(f'send_kv: {self.name}: to[{dst}]: {s}')

        return self.send(self.bcast, s)

    def cast_kv(self, tmsg):

        log(f'cast_kv: msg: {tmsg}')

        return self.send_kv(self.bcast, tmsg)

    def on_cmd_null(self, from_name, src, cmd, msg):

        log(f'{self.name}: from {src}: null: cmd: {msg}')

        return None

    def recv_kv(self, src, eload):

        log(f'recv_kv: eload: {eload}')
        split = eload.split(b' ')
        signature = split[-1]
        data = b' '.join(split[:-1])

        kvs = dict()
        log(f'recv_kv: split: {split}')
        for part in split:
            k, v = part.split(b':')
            kvs[k] = v

        verified = False
        name = kvs.get(b'name')
        log(f'recv_kv: name: {name}')
        if name is not None and signature.startswith(b'signature:'):
            name = decode_base64(name)
            signature = signature.split(b':')[-1]
            signature = decode_base64(signature)
            log(f'recv_kv: signature: {signature}')
            verified = openssl_verify(name.decode(), signature, data)
            log(f'recv_kv: verified: {verified}')
        else:
            log(f'recv_kv: sig: {signature}')
            signature = None

        omsg = dict()
        cmsg = dict()
        if verified:
            for k, v in kvs.items():
                    v = decode_base64(v)
                    if v and k not in self.core_msg:
                        omsg[k] = v
                    elif v:
                        cmsg[k] = v
                    else:
                        log(f'recv_kv: bad v: {v}')

            if set(cmsg.keys()) - self.core_msg:
                log(f'recv_kv: not all core msg: {set(cmsg.keys())}')
                omsg = dict()
            elif cmsg[b'mac'] != src:
                log(f'recv_kv: src mismatch: msg[{cmsg[b"mac"]}] vs pkt[{src}]')
                omsg = dict()

        cmd = omsg.get(b'cmd')
        log(f'recv_kv: cmd: {cmd}')
        if isinstance(cmd, bytes):
            cmd = cmd.decode()
            name = name.decode()
            handler = getattr(self, f'on_cmd_{cmd}', self.on_cmd_null)
            return handler(name, src, cmd, omsg)

        return None

    def on_ekl_bcast_kv(self, src, eload):

        return self.recv_kv(src, eload)

    def on_ekl_bcast(self, src, eload):

        log(f'server: ekl_bcast: {src}: {eload}')

        if eload.startswith(b'type:kv '):

            return self.on_ekl_bcast_kv(src, eload)

        return None

    def on_ekl(self, dst, src, eload):

        if dst == self.bcast:

            return self.on_ekl_bcast(src, eload)

        return None

    def on_epkt(self, dst, src, etype, eload):

        if etype == self.etype:

            return self.on_ekl(dst, src, eload)

        return None

    def run_one(self):

        pkt = self.so.recv(2**16)
        log(f'recv pkt: len={len(pkt)}')
        if len(pkt) >= self.ehdr_len:
            dst = pkt[:self.eaddr_len]
            src = pkt[self.eaddr_len:self.eaddr_len*2]
            etype = pkt[self.eaddr_len*2:self.eaddr_len*2 + 2]
            etype, = self.etype_s.unpack(etype)
            eload = pkt[self.eaddr_len*2 + 2:]

            return self.on_epkt(dst, src, etype, eload)

        return None

    def idle(self):

        while True:

            self.run_one()


class ClientKL(KernelLoader):

    def wait(self):

        self.idle()

    def on_cmd_hello(self, from_name, src, cmd, msg):

        log(f'client[{self.name}]: cmd_hello: from[{from_name}--{src}]: {msg}')

        return self.send_hello_ack(src)

    def send_hello_ack(self, dst):

        msg = {
            'cmd': 'hello_ack',
        }

        return self.send_kv(dst, msg)


class ServerKL(KernelLoader):

    def send_hello(self):

        msg = {
            'cmd': b'hello',
        }

        self.cast_kv(msg)

        return None

    def on_cmd_hello_ack(self, from_name, src, cmd, msg):

        log(f'server[{self.name}]: cmd_hello_ack: from[{from_name}--{src}]: {msg}')

        return None


def server_main(sys_args):

    log(f'server_main({sys_args})')

    server = ServerKL(sys_args.name, sys_args.iface)
    server.send_hello()
    server.idle()

    return 0


def client_main(sys_args):

    log(f'client_main({sys_args})')

    client = ClientKL(sys_args.name, sys_args.iface)

    client.wait()

    return 0


class ModesRun(EnumHelper):

    server = server_main
    client = client_main


def main(sys_args, *args, **kwargs):

    log(f'main({sys_args})')

    mode = Modes(sys_args.mode)
    mode_runner = ModesRun.get(mode.value)

    if mode_runner:
        try:
            return mode_runner(sys_args)
        except KeyboardInterrupt:
            log('...exiting')

    return 1


log = print


if __name__ == '__main__':

    import argparse
    import logging

    parser = argparse.ArgumentParser(description='Kernel loader.')
    parser.add_argument('--name', type=str, required=True, help='Name of what.')
    parser.add_argument('--dir', type=str, default='./', help='Where to operate.')
    parser.add_argument('--mode', choices=Modes.values(), default=Modes.Server.value, help='Mode of the loader.')
    parser.add_argument('--iface', type=str, default='', help='Interface to use.')

    args = parser.parse_args(sys.argv[1:])

    log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s] " + args.name + " %(message)s")
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(f'kl-{args.name}-{os.getpid()}.log')
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    root_logger.addHandler(console_handler)

    log = logging.getLogger().info

    sys.exit(main(args))
