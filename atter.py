
import collections
import datetime
from enum import Enum
import pytz
import logging
import os
import random
import subprocess
import sys
import time

log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(f'atter-{os.getpid()}.log')
file_handler.setFormatter(log_formatter)
root_logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
root_logger.addHandler(console_handler)


log = logging.getLogger().info


def time_():

    return datetime.datetime.utcnow().timestamp()


def dt_to_string(dt):

    fmt = '%Y-%m-%d %H:%M:%S %Z%z'

    return dt.strftime(fmt)


class Atter(object):

    def __init__(self, tz):

        # time -> set(fn)
        self.todos = collections.defaultdict(set)
        self.tz = tz

    def add(self, time_, fn):

        self.todos[time_].add(fn)

    def run_one(self):

        now = time_()
        for when in sorted(filter(lambda t: t < now, self.todos.keys())):
            log(f'running: {self.todos[when]}')
            for x in self.todos[when]:
                x(self, when)
            self.todos.pop(when)

    def time(self):

        return time_()

    def run(self):

        while True:
            self.run_one()
            next_ = min(self.todos.keys()) if self.todos else None
            if next_ is None:
                break
            now = self.time()
            wait = max(next_ - now, 0)
            next_utc = datetime.datetime.utcfromtimestamp(next_).astimezone(self.tz)
            log(f'waiting for {wait}s [until {dt_to_string(next_utc)}]')
            time.sleep(wait)


def make_repeater(interval, fn, name=None, args=tuple(), kwargs=dict()):

    def repeater(atter, when):

        log(f'repeater running[{name if name else "unnamed"}--{interval}]: {fn}')
        fn(*args, **kwargs)
        now = time_()
        next_ = ((now // interval) + 1) * interval
        
        atter.add(next_, repeater)

    return repeater


def make_oneoff(fn, name=None, args=tuple(), kwargs=dict()):

    def repeater(atter, when):

        log(f'repeater running[{name if name else "unnamed"}]: {fn}')
        fn(*args, **kwargs)

    return repeater


def make_exec_repeater(cmd_args, *args, **kwargs):

    name = kwargs.get('name')

    def exec_fn(args_):

        log(f'exec repeater running[{name if name else "unnamed"}]: \'{" ".join(args_)}\'')
        try:
            subprocess.check_call(args_)
        except subprocess.CalledProcessError as cpe:
            log(f'exec repeater error: \'{cpe}\'')

    kwargs['args'] = tuple((cmd_args,))

    return make_repeater(*args + (exec_fn,), **kwargs)


def make_exec_oneoff(cmd_args, *args, **kwargs):

    name = kwargs.get('name')

    def exec_fn(args_):

        log(f'exec repeater running[{name if name else "unnamed"}]: \'{" ".join(args_)}\'')
        try:
            subprocess.check_call(args_)
        except subprocess.CalledProcessError as cpe:
            log(f'exec repeater error: \'{cpe}\'')

    kwargs['args'] = tuple((cmd_args,))

    return make_oneoff(*args + (exec_fn,), **kwargs)


class EnumHelper(Enum):

    @classmethod
    def values(cls):

        return set(v.value for v in cls.__members__.values())


class Types(EnumHelper):

    ExecRepeat = 'exec-repeat'
    ExecOneoff = 'exec-oneoff'


class Intervals(EnumHelper):

    Second = 'second'
    Minute = 'minute'
    Hour = 'hour'
    Day = 'day'


class RIntervals(EnumHelper):

    second = 1
    minute = 60
    hour = 60 * 60
    day = 24 * 60 * 60


def main(args, cmd_args):

    timezone = args.tz
    hour_minute_second = args.start
    interval = args.interval
    multiplier = args.multiplier
    type_ = args.type

    plus = hour_minute_second[0] == '+'
    if plus:
        log('differential time start')
    hour_minute_second = hour_minute_second[1 * int(plus):].split(':')

    log(f'timezone: {timezone}')
    tz = pytz.timezone(timezone)

    hour = 0
    minute = 0
    second = 0

    if len(hour_minute_second) == 1:
        second = hour_minute_second[0]
        log(f'waiting for {second}s')
        plus = True
    elif len(hour_minute_second) in {2, 3}:
        hour = hour_minute_second[0]
        minute = hour_minute_second[1]
        log(f'waiting until {hour}h')
        log(f'waiting until {minute}m')
    if len(hour_minute_second) == 3:
        second = hour_minute_second[2]
        second = int(second)
        log(f'waiting until {second}s')
        
    hour = int(hour) % 24
    minute = int(minute) % 60
    second = int(second) % 60

    log(f'waiting until {"+" if plus else ""}{hour}:{minute}:{second}')

    interval = RIntervals[interval].value * multiplier

    dt_utcnow = datetime.datetime.utcnow()
    dt_now = dt_utcnow + tz.utcoffset(datetime.datetime.now())

    if timezone.lower() == 'utc':
        log('Using UTC')
        dt_now = dt_utcnow

    if not plus:
        wait_hour = ((hour - dt_now.hour + 24) % 24)
        wait_minute = ((minute - dt_now.minute + 60) % 60)
        wait_second = (60 - dt_now.second)
    else:
        wait_hour = hour
        wait_minute = minute
        wait_second = second

    log(f'wait offset: {wait_hour}:{wait_minute}:{wait_second}')
    wait = wait_hour * 60 * 60 + wait_minute * 60 + wait_second

    start = dt_utcnow.timestamp() + wait
    log(f'wait: {wait}, start: {start}, dt_now: {dt_now.timestamp()}, now: {time_()}, diff: {start - dt_now.timestamp()}, difft: {time_() - dt_now.timestamp()}')

    atter = Atter(tz)

    if args.type == Types.ExecRepeat.value:
        reppy = make_exec_repeater(cmd_args, interval)
        atter.add(start, reppy)
    elif args.type == Types.ExecOneoff.value:
        reppy = make_exec_oneoff(cmd_args)
        atter.add(start, reppy)

    try:
        atter.run()
    except KeyboardInterrupt:
        pass

    return 0


if __name__ == '__main__':

    import argparse

    parser = argparse.ArgumentParser(description='Do things at.')
    parser.add_argument('--start', type=str, default='+1', help='When to first at.')
    parser.add_argument('--type', choices=Types.values(), default='exec-oneoff', help='Way of doing things.')
    parser.add_argument('--tz', type=str, default='UTC', help='Timezone string.')
    parser.add_argument('--interval', choices=Intervals.values(), default=Intervals.Hour, help='Interval for thing to happen.')
    parser.add_argument('--multiplier', type=float, default=1., help='Multiplier for interval.')

    args, cmd_args = parser.parse_known_args(sys.argv)

    sys.exit(main(args, cmd_args[1:]))
