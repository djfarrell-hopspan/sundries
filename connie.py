
import collections
import enum
import logging
import numpy
import os
import sys
import time

import eventio


class ConnieDB(object):

    db_dir_name = 'connie_db'

    FiveTuple = collections.namedtuple('FiveTuple', ['proto', 'src', 'dst', 'sport', 'dport'])
    FiveTupleKeys = set(k.encode() for k in FiveTuple._fields)
    DirTuple = collections.namedtuple('DirTuple', ['src', 'dst', 'sport', 'dport', 'packets', 'bytes'])
    DirTupleKeys = set(k.encode() for k in DirTuple._fields)
    FullTuple = collections.namedtuple('FullTuple', [
        'previous_second',
        'second',
        'proto',
        'src',
        'dst',
        'sport',
        'dport',
        'start_rx_bytes',
        'end_rx_bytes',
        'start_tx_bytes',
        'end_tx_bytes',
        'start_rx_packets',
        'end_rx_packets',
        'start_tx_packets',
        'end_tx_packets'
    ])

    four_tuple_protos = {b'udp', b'tcp', b'sctp'}
    all_protos = four_tuple_protos | {b'icmp'}

    def __init__(self, connie, track):

        try:
            os.mkdir(os.path.join('./', self.db_dir_name))
        except IOError:
            pass
        except OSError:
            pass

        self.track = tuple(track.encode().split(b',')) if track else None
        self.connie = connie
        self.connie.on_conntrack_data = self.on_conntrack_data
        self.previous_connections = {}
        self.connections = {}

    def to_kv(self, line):

        logd(f'to_kv: {line}')
        ret = {}
        for part in line.split():
            if part.count(b'=') == 1:
                k, v = part.split(b'=')
                ret[k] = v
        logd(f'to_kv: {ret}')

        return ret

    def on_conntrack_data(self, when, lines):

        log(f'number of connections: {len(self.connections)}')

        previous_connections = set(self.connections.keys())

        self.previous_connections.clear()
        self.previous_connections.update(self.connections)
        self.connections.clear()

        number_skipped = 0
        for line in lines:
            src1 = line.find(b'src')
            src2 = line.find(b'src', src1 + 1)

            if not -1 in {src1, src2}:
                pre_split = line[:src1].split()
                if len(pre_split) >= 5:
                    proto = pre_split[2]
                    if proto in self.all_protos:
                        originator = self.to_kv(line[src1:src2])
                        o_src = originator.get(b'src')
                        if not o_src or (self.track and not o_src.startswith(self.track)):
                            number_skipped += 1
                            continue
                        destinator = self.to_kv(line[src2:])
                        if proto in self.four_tuple_protos:
                            ftd = {k: originator.get(k.encode()) for k in self.FiveTuple._fields}
                            logd(f'{ftd}')
                            ftd.update({'proto': proto})
                            logd(f'{ftd}')
                            o_five_tuple = self.FiveTuple(**ftd)
                            o_dir_tuple = self.DirTuple(**{k: originator.get(k.encode()) for k in self.DirTuple._fields})
                            d_dir_tuple = self.DirTuple(**{k: destinator.get(k.encode()) for k in self.DirTuple._fields})
                            prev_full_tuple = self.previous_connections.get(o_five_tuple,
                                self.FullTuple(*((None, when - 1,) + (None,) * 5  + (0,) * 8)))
                            full_tuple = self.FullTuple(
                                previous_second=prev_full_tuple.second,
                                second=when,
                                proto=o_five_tuple.proto.decode(),
                                src=o_five_tuple.src.decode(),
                                dst=o_five_tuple.dst.decode(),
                                sport=int(o_five_tuple.sport),
                                dport=int(o_five_tuple.dport),
                                start_rx_bytes=int(prev_full_tuple.end_rx_bytes),
                                start_rx_packets=int(prev_full_tuple.end_rx_packets),
                                end_rx_bytes=int(d_dir_tuple.bytes),
                                end_rx_packets=int(d_dir_tuple.packets),
                                start_tx_bytes=int(prev_full_tuple.end_tx_bytes),
                                start_tx_packets=int(prev_full_tuple.end_tx_packets),
                                end_tx_bytes=int(o_dir_tuple.bytes),
                                end_tx_packets=int(o_dir_tuple.packets),
                            )
                            self.connections[o_five_tuple] = full_tuple

                            logd(f'{full_tuple}')

        connections = set(self.connections.keys())
        common = previous_connections & connections
        finished = previous_connections - common
        new = connections - common
        log(f'number of skipped connections: {number_skipped}')
        log(f'number of new connection: {len(new)}')
        log(f'number of finished connection: {len(finished)}')




class ConnieHandler(eventio.PopenHandler):

    class Modes(enum.Enum):

        ConntrackPreTime = 'ConntrackPreTime'
        Conntrack = 'Conntrack'
        IpPreTime = 'IpPreTime'
        Ip = 'Ip'
        ArpPreTime = 'ArpPreTime'
        Arp = 'Arp'
        NeighPreTime = 'NeighPreTime'
        Neigh = 'Neigh'
        RejectsPreTime = 'RejectsPreTime'
        Rejects = 'Rejects'
        Done = 'Done'

        Error = 'Error'

    major_modes = {
        Modes.Conntrack,
        Modes.Ip,
        Modes.Arp,
        Modes.Neigh,
        Modes.Rejects,
    }

    valid_transitions = {
        (None, Modes.ConntrackPreTime),
        (Modes.ConntrackPreTime, Modes.Conntrack),
        (Modes.Conntrack, Modes.IpPreTime),
        (Modes.IpPreTime, Modes.Ip),
        (Modes.Ip, Modes.ArpPreTime),
        (Modes.ArpPreTime, Modes.Arp),
        (Modes.Arp, Modes.NeighPreTime),
        (Modes.NeighPreTime, Modes.Neigh),
        (Modes.Neigh, Modes.RejectsPreTime),
        (Modes.RejectsPreTime, Modes.Rejects),
        (Modes.Rejects, Modes.Done),
        (Modes.Done, Modes.ConntrackPreTime),
        (Modes.Error, Modes.ConntrackPreTime),
    }

    def __init__(self, connie_name, cmd_args):

        self.cmd_args = cmd_args

        eventio.PopenHandler.__init__(self, connie_name, cmd_args)

        self.stdout_liner = eventio.LineMixin(connie_name)
        self.stdout_liner.on_line = self.on_stdout_line

        self.stderr_liner = eventio.LineMixin(connie_name)
        # Major mode -> time
        self.major_mode_times = dict()
        # Major mode -> list()
        self.major_mode_lines = {x: list() for x in self.major_modes}
        self.__prev_mode = None
        self.__mode = None
        self.conntrack_times = list()
        self.conntrack_times_offsets = list()
        self.iteration_second = None

    def on_flush_fd(self, fd):

        logw(f'{self.name}: flush fd: {fd}')

        if self.stderr is not None and self.stderr.fileno() == fd:
            self.on_flush_stderr()
        elif self.stdout is not None and self.stdout.fileno() == fd:
            self.on_flush_stdout()

    def on_flush_stdout(self):

        self.stdout_line.on_flush_line()

    def on_flush_stderr(self):

        self.stderr_line.on_flush_line()

    def on_stdout(self, data):

        logd(f'{self.name}: on stdout: {len(data)}')
        self.stdout_liner.on_line_data(data)

    def on_stderr(self, data):

        logd(f'{self.name}: on stderr: {len(data)}')
        self.stderr_liner.on_line_data(data)

    def on_stdout_line(self, line):

        if line.startswith(b'*******************'):
            if line.startswith(b'*******************conntrack'):
                self.mode = self.Modes.ConntrackPreTime
            elif line.startswith(b'*******************ip'):
                self.mode = self.Modes.IpPreTime
            elif line.startswith(b'*******************arp'):
                self.mode = self.Modes.ArpPreTime
            elif line.startswith(b'*******************neigh'):
                self.mode = self.Modes.NeighPreTime
            elif line.startswith(b'*******************rejects'):
                self.mode = self.Modes.RejectsPreTime
            elif line.startswith(b'*******************done'):
                self.mode = self.Modes.Done
            else:
                self.mode = self.Modes.Error
        elif line.startswith(b'time='):
            mode_time = float(line[5:])
            curr_mode_value = self.mode.value
            if curr_mode_value.endswith('PreTime'):
                next_mode_value = curr_mode_value[:curr_mode_value.find('PreTime')]
                try:
                    self.mode = self.Modes(next_mode_value)
                    self.major_mode_times[self.mode] = mode_time, time.time()
                except ValueError:
                    loge(f'{self.name}: could not decode mode for time: {next_mode_value}')
                    self.mode = self.Modes.Error
            else:
                self.mode = self.Modes.Error
        else:
            if self.mode in self.major_modes:
                self.major_mode_lines[self.mode].append(line)

    @property
    def mode(self):

        return self.__mode

    @property
    def prev_mode(self):

        return self.__prev_mode

    @mode.setter
    def mode(self, rhs):

        log(f'{self.name}: new mode: {rhs.value}, old mode: {self.__mode.value if self.__mode else None}')

        transition = (self.__mode, rhs)
        error = transition not in self.valid_transitions

        self.__prev_mode = self.__mode
        if error:
            loge(f'{self.name}: invalid mode transition: {transition}')
            self.__mode = self.Modes.Error
        else:
            self.__mode = rhs
            if self.__prev_mode in self.major_modes:
                prev_mode_value = self.__prev_mode.value
                if hasattr(self, 'on_' + prev_mode_value):
                    handler = getattr(self, 'on_' + prev_mode_value, self.on_Error)
                    handler()
                    try:
                        self.major_mode_lines[self.prev_mode].clear()
                    except Exception as e:
                        loge(f'{self.name}: error clearing mode line list: {e}')

    def on_ConntrackPreTime(self):

        pass

    def on_Conntrack(self):

        self.conntrack_times.append(self.major_mode_times[self.prev_mode][1])
        self.conntrack_times = self.conntrack_times[:20]

        self.conntrack_times_offsets.append(self.major_mode_times[self.prev_mode][1] % 1)
        self.conntrack_times_offsets = self.conntrack_times_offsets[:20]
        offset = numpy.median(self.conntrack_times_offsets)
        self.iteration_second = int(self.major_mode_times[self.prev_mode][1] - offset)

        log(f'{self.name}: finished {self.prev_mode.value}, {self.iteration_second}')
        self.on_conntrack_data(self.iteration_second, self.major_mode_lines[self.prev_mode])

    def on_conntrack_data(self, when, data):

        pass

    def on_IpPreTime(self):

        pass

    def on_Ip(self):

        log(f'{self.name}: finished {self.prev_mode.value}, {self.iteration_second}')

    def on_ArpPreTime(self):

        pass

    def on_Arp(self):

        log(f'{self.name}: finished {self.prev_mode.value}, {self.iteration_second}')

    def on_NeighPreTime(self):

        pass

    def on_Neigh(self):

        log(f'{self.name}: finished {self.prev_mode.value}, {self.iteration_second}')

    def on_RejectsPreTime(self):

        pass

    def on_Rejects(self):

        log(f'{self.name}: finished {self.prev_mode.value}, {self.iteration_second}')

    def on_Done(self):

        pass

    def on_Error(self):

        pass

def main_connie(name, track, cmd_args):

    poller = eventio.Poller()
    connie = ConnieHandler(name, cmd_args)
    connie_db = ConnieDB(connie, track)
    poller.add_handler(connie)

    poller.run()

    return 0


def main(args, cmd_args):

    name = args.name
    log(f'{name}: changing to dir: {args.dbdir}')
    os.chdir(args.dbdir)

    return main_connie(name, args.track, cmd_args)


if __name__ == '__main__':

    import argparse

    parser = argparse.ArgumentParser(description='Connection tracker.')
    parser.add_argument('--name', type=str, required=True, help='Name of this connie instance.')
    parser.add_argument('--dbdir', type=str, default='./', help='Where to store the DB.')
    parser.add_argument('--track', type=str, default=None, help='Which subnets to track (as source).')
    parser.add_argument('--debug', default=False, action='store_true', help='Enable debug printing.')

    args, cmd_args = parser.parse_known_args()

    log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s] " + args.name + " %(message)s")
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO if not args.debug else logging.DEBUG)

    file_handler = logging.FileHandler(os.path.join(args.dbdir, f'connie-{args.name}-{int(time.time()):010d}-{os.getpid()}.log'))
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    root_logger.addHandler(console_handler)

    log = logging.getLogger().info
    logw = logging.getLogger().warning
    loge = logging.getLogger().error
    logd = logging.getLogger().debug

    eventio.set_logfns(log, logw, loge, logd)

    sys.exit(main(args, cmd_args))
