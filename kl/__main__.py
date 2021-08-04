
import argparse
import functools
import logging
import os
import sys


from . import enumhelper
import eventio
from . import kldetails
from . import klevent
from . import set_logfns
from . import transports

def server_main(sys_args):

    log(f'server_main({sys_args})')
    if sys_args.to is None:

        loge(f'Need "--to" in server mode')
        raise SystemExit(1)

    name = sys_args.name.encode()
    transport_class = transports.RTransports.get(sys_args.transport).value
    transport = transport_class(name, addr_info=sys_args.addrinfo, out_going=True, to=sys_args.to.encode())
    server_handler = klevent.make_kl_server_handler(name, transport,)
    poller = eventio.Poller()
    poller.add_handler(server_handler)
    poller.run()

    return 0


def client_main(sys_args):

    log(f'client_main({sys_args})')

    name = sys_args.name.encode()
    transport_class = transports.RTransports.get(sys_args.transport).value
    transport = transport_class(name, addr_info=sys_args.addrinfo, out_going=False)
    client_handler = klevent.make_kl_client_handler(name, transport)
    poller = eventio.Poller()
    poller.add_handler(client_handler)
    poller.run()

    return 0


class ModesRun(enumhelper.EnumHelper):

    server = server_main
    client = client_main


def main(sys_args, *args, **kwargs):

    mode = kldetails.Modes(sys_args.mode)
    mode_runner = ModesRun.get(mode.value)

    if mode_runner:
        try:
            os.chdir(sys_args.rdir)
            return mode_runner(sys_args)
        except KeyboardInterrupt:
            log('...exiting')

    return 1


parser = argparse.ArgumentParser(description='Kernel loader.')
parser.add_argument('--name', type=str, required=True, help='Name of what.')
parser.add_argument('--rdir', type=str, default='./', help='Where to operate.')
parser.add_argument('--mode', choices=kldetails.Modes.values(), default=kldetails.Modes.Server.value, help='Mode of the loader.')
parser.add_argument('--iface', type=str, default='', help='Interface to use.')
parser.add_argument('--transport', choices=transports.Transports.values(), required=True, help='Transport to use.')
parser.add_argument('--addrinfo', type=str, required=True, help='Addrinfo for transport.')
parser.add_argument('--to', type=str, default=None, help='Name of where to connect to.')
parser.add_argument('--debug', default=False, action='store_true', help='Enable debug printing.')

args = parser.parse_args(sys.argv[1:])

log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s] " + args.name + " %(message)s")
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO if not args.debug else logging.DEBUG)

file_handler = logging.FileHandler(os.path.join(args.rdir, f'kl-{args.name}-{os.getpid()}.log'))
file_handler.setFormatter(log_formatter)
root_logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
root_logger.addHandler(console_handler)

log = logging.getLogger().info
logw = logging.getLogger().warning
loge = logging.getLogger().error
logd = logging.getLogger().debug

set_logfns(log, logw, loge, logd)

sys.exit(main(args))
