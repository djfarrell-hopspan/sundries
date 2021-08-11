
import collections
import datetime
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
    FullTuple_ = collections.namedtuple('FullTuple', [
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
    ], defaults=[
        0,
        0,
        None,
        None,
        None,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ])

    class FullTuple(FullTuple_):

        TotalDiff = collections.namedtuple('TotalDiff', [
            'rx_Mbps',
            'rx_pps',
            'tx_Mbps',
            'tx_pps',
            'duration',
            'rx_bytes',
            'tx_bytes',
            'rx_packets',
            'tx_packets',
        ])

        add_fields = {
            'start_rx_bytes',
            'start_tx_bytes',
            'end_rx_bytes',
            'end_tx_bytes',
            'start_rx_packets',
            'start_tx_packets',
            'end_rx_packets',
            'end_tx_packets',
        }

        diff_pairs = {
            ('start_rx_bytes', 'end_rx_bytes'),
            ('start_tx_bytes', 'end_tx_bytes'),
            ('start_rx_packets', 'end_rx_packets'),
            ('start_tx_packets', 'end_tx_packets'),
        }

        def __add__(self, rhs):

            new_tuple = self.__class__(**{
                k: getattr(self, k) if k not in self.add_fields else \
                        getattr(self, k) + getattr(rhs, k) \
                            for k in self._fields})

            return new_tuple

        def __iadd__(self, rhs):

            new_tuple = self.__add__(rhs)

            return new_tuple

        def __lt__(self, rhs):

            return ((self.end_tx_bytes - self.start_tx_bytes) \
                    + (self.end_rx_bytes - self.start_rx_bytes)) \
                        < ((rhs.end_tx_bytes - rhs.start_tx_bytes) \
                            + (rhs.end_rx_bytes - rhs.start_rx_bytes))

        def adjust_diff(self, rhs):

            spte_packets = self.end_tx_packets
            spre_packets = self.end_rx_packets
            rpte_packets = rhs.end_tx_packets
            rpre_packets = rhs.end_rx_packets

            sbte_bytes = self.end_tx_bytes
            sbre_bytes = self.end_rx_bytes
            rbte_bytes = rhs.end_tx_bytes
            rbre_bytes = rhs.end_rx_bytes

            spts_packets = self.start_tx_packets
            sprs_packets = self.start_rx_packets
            rpts_packets = rhs.start_tx_packets
            rprs_packets = rhs.start_rx_packets

            sbts_bytes = self.start_tx_bytes
            sbrs_bytes = self.start_rx_bytes
            rbts_bytes = rhs.start_tx_bytes
            rbrs_bytes = rhs.start_rx_bytes

            new_tuple = self.__class__(
                second=rhs.second,
                previous_second=rhs.previous_second,
                src=self.src,
                start_rx_bytes=sbre_bytes,
                start_tx_bytes=sbte_bytes,
                start_rx_packets=rpre_packets,
                start_tx_packets=rpte_packets,
                end_rx_bytes=sbre_bytes + rbre_bytes - rbrs_bytes,
                end_tx_bytes=sbte_bytes + rbte_bytes - rbts_bytes,
                end_rx_packets=spre_packets + rpre_packets - rprs_packets,
                end_tx_packets=spte_packets + rpte_packets - rpts_packets,
            )

            return new_tuple

        def has_change(self):

            return \
                self.start_rx_bytes != self.end_rx_bytes \
                or self.start_tx_bytes != self.end_tx_bytes

        def total_diff(self, previous):

            seconds = float(self.second - previous.second)
            rx_B = self.end_rx_bytes - self.start_rx_bytes
            tx_B = self.end_tx_bytes - self.start_tx_bytes
            rx_p = self.end_rx_packets - self.start_rx_packets
            tx_p = self.end_tx_packets - self.start_tx_packets

            return self.TotalDiff(
                rx_Mbps=(8 * rx_B / seconds) / 2**20,
                tx_Mbps=(8 * tx_B / seconds) / 2**20,
                rx_pps=rx_p / seconds,
                tx_pps=tx_p / seconds,
                duration=seconds,
                rx_bytes=rx_B,
                tx_bytes=tx_B,
                rx_packets=rx_p,
                tx_packets=tx_p,
            )

        def diff(self):

            seconds = float(self.second - self.previous_second)
            rx_B = self.end_rx_bytes - self.start_rx_bytes
            tx_B = self.end_tx_bytes - self.start_tx_bytes
            rx_p = self.end_rx_packets - self.start_rx_packets
            tx_p = self.end_tx_packets - self.start_tx_packets

            return self.TotalDiff(
                rx_Mbps=(8 * rx_B / seconds) / 2**20,
                tx_Mbps=(8 * tx_B / seconds) / 2**20,
                rx_pps=rx_p / seconds,
                tx_pps=tx_p / seconds,
                duration=seconds,
                rx_bytes=rx_B,
                tx_bytes=tx_B,
                rx_packets=rx_p,
                tx_packets=tx_p,
            )

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
        self.connie.on_neigh_data = self.on_neigh_data
        self.connie.on_done = self.on_done
        self.previous_connections = {}
        self.connections = {}
        self.connections_by_ip = {}
        self.total = None
        self.ips = {}
        self.previous_ips = {}
        self.new_connections = None
        self.finished_connections = None
        self.total_diff = None

    def to_kv(self, line):

        logd(f'to_kv: {line}')
        ret = {}
        for part in line.split():
            if part.count(b'=') == 1:
                k, v = part.split(b'=')
                ret[k] = v
        logd(f'to_kv: {ret}')

        return ret

    def on_done(self, when):

        sorted_connections = sorted(self.connections.items(), key=lambda x: x[1])
        log('*' * 80)
        for _, connection in sorted_connections[-5:]:
            diff = connection.diff()
            log(f'top connection: rx rate: {diff.rx_Mbps:7.3f}, tx rate: {diff.tx_Mbps:7.3f}, {connection.src}->{connection.dst} ')

        log('*' * 80)

        self.update_conntrack_db(when)

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
                        o_dst = originator.get(b'dst')
                        if not o_src or not o_dst \
                                or (self.track and \
                                    (not o_src.startswith(self.track) \
                                        or o_dst.startswith(self.track))):
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

        self.new_connections = new
        self.finished_connections = finished

        if self.total is None:
            self.total = self.FullTuple(*((when - 2, when - 1,) + (None,) * 5 + (0,) * 8))
        new_total = self.FullTuple(*((self.total.second, when,) + (None,) * 5 + (0,) * 8))
        self.connections_by_ip.clear()
        for c in connections:

            c_ = self.connections.get(c)
            new_total += c_

            existing_by_ip = self.connections_by_ip.get(c.src)
            if existing_by_ip is not None and c_.has_change():
                self.connections_by_ip[c.src].adjust_diff(c_)
            else:
                self.connections_by_ip[c.src] = self.FullTuple(
                    src=c.src,
                )

        for f in finished:
            try:
                self.connections_by_ip.pop(c)
            except KeyError:
                pass

        self.total_diff = new_total.total_diff(self.total)
        log(f'totals: {self.total_diff}')
        self.total = new_total
        
    def on_neigh_data(self, when, lines):

        self.previous_ips.clear()
        self.previous_ips.update(self.ips)

        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
                mac = parts[5]
                if ip.startswith(self.track):
                    self.ips[ip] = mac

        previous = set(self.previous_ips.keys()) 
        current = set(self.ips.keys())
        common = current & previous
        new = current - common
        old = previous - common

        log(f'number of ip addresses: {len(current)}')
        log(f'number of new ip addresses: {len(new)}')
        log(f'number of old ip addresses: {len(old)}')

    def update_conntrack_db(self, when):

        udt = datetime.datetime.utcfromtimestamp(float(when))

        year = f'{udt.year:04d}'
        month = f'{udt.month:02d}'
        day = f'{udt.day:1d}'
        hour = f'{udt.hour:02d}'
        minute = f'{udt.minute:02d}'

        dir_path = os.path.join('.',
            year,
            year + month,
            year + month + day,
            year + month + day + hour,
            year + month + day + year + minute + 'UTC',
        )

        connections_dir = os.path.join(dir_path, 'connections')
        rates_dir = os.path.join(dir_path, 'rates')
        ends_dir = os.path.join(dir_path, 'ends')
        latest_second_path = os.path.join('.', 'latest')
        total_rate_path = os.path.join('.', 'total_rate')
        total_ip_rate_path = os.path.join('.', 'total_ip_rates')

        log(f'when dir: {when}, {dir_path}')


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
            if self.__mode == self.Modes.Done:
                self.on_Done()

    def on_ConntrackPreTime(self):

        pass

    def on_Conntrack(self):

        self.conntrack_times.append(self.major_mode_times[self.prev_mode][1])
        self.conntrack_times = self.conntrack_times[:20]

        self.conntrack_times_offsets.append(self.major_mode_times[self.prev_mode][1] % 1)
        self.conntrack_times_offsets = self.conntrack_times_offsets[:20]
        offset = numpy.median(self.conntrack_times_offsets)
        log(f'iteration offset: {offset}')
        old_second = self.iteration_second
        self.iteration_second = int(self.major_mode_times[self.prev_mode][1] - offset + 0.5)

        log(f'{self.name}: iteration second: {self.prev_mode.value}, {self.iteration_second}')
        if self.iteration_second and old_second and (self.iteration_second - old_second != 1):
            loge(f'bad iteration second change: {self.iteration_second - old_second}')

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
        self.on_neigh_data(self.iteration_second, self.major_mode_lines[self.prev_mode])

    def on_neigh_data(self, when, lines):

        pass

    def on_RejectsPreTime(self):

        pass

    def on_Rejects(self):

        log(f'{self.name}: finished {self.prev_mode.value}, {self.iteration_second}')

    def on_Done(self):

        log(f'{self.name}: finished {self.mode.value}, {self.iteration_second}')
        self.on_done(self.iteration_second)

    def on_done(self, when):

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
