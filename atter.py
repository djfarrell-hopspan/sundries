
import collections
import datetime
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

def dt_to_string(dt):

    fmt = '%Y-%m-%d %H:%M:%S %Z%z'

    return dt.strftime(fmt)

class Atter(object):

    def __init__(self, tz):

        # time -> set(fn)
        self.todos = collections.defaultdict(set)
        self.tz = tz

    def add(self, time_, fn):

        if time_ > time.time():
            self.todos[time_].add(fn)
        else:
            self.todos[time.time() + 60].add(fn)

    def run_one(self):

        now = time.time()
        for when in sorted(filter(lambda t: t < now, self.todos.keys())):
            log(f'running: {self.todos[when]}')
            for x in self.todos[when]:
                x(self, when)
            self.todos.pop(when)

    def run(self):

        while True:
            self.run_one()
            next_ = min(self.todos.keys()) if self.todos else None
            if next_ is None:
                break
            now = time.time()
            wait = max(next_ - now, 0)
            next_utc = datetime.datetime.utcfromtimestamp(next_).astimezone(self.tz)
            log(f'waiting for {wait}s [until {dt_to_string(next_utc)}]')
            time.sleep(wait)


def make_repeater(interval, fn, args=tuple(), kwargs=dict()):

    def repeater(atter, when):

        fn(*args, **kwargs)
        atter.add(when + interval, repeater)

    return repeater


def make_exec_repeater(cmd_args, *args, **kwargs):

    def exec_fn(args_):

        log(f'running: \'{" ".join(args_)}\'')
        try:
            subprocess.check_call(args_)
        except subprocess.CalledProcessError as cpe:
            log(f'exec repeater error: \'{cpe}\'')

    kwargs['args'] = tuple((cmd_args,))

    return make_repeater(*args + (exec_fn,), **kwargs)


def usage():

    log(f'{sys.argv[0]} <timezone, e.g. Australia/Sydney> <hour of day:minute of day> <second|minute|hourly|daily> <multiplier>')

    return 1


def main():

    if len(sys.argv) < 4:

        return usage()


    _, timezone, \
        hour_minute, \
        interval, \
        multiplier = sys.argv[:5]

    cmd_args = sys.argv[5:]

    hour, minute = hour_minute.split(':')
    hour = int(hour) % 24
    minute = int(minute) % 60
    multiplier = float(multiplier)
    intervals = {
        'second': 1,
        'minute': 60,
        'hour': 60 * 60,
        'daily': 24 * 60 * 60,
    }
    interval = intervals.get(interval, hour) * multiplier

    tz = pytz.timezone(timezone)

    dt_utcnow = datetime.datetime.utcnow()
    dt_now = tz.localize(dt_utcnow)
    if timezone.lower() == 'utc':
        dt_now = dt_utcnow
    wait_hour = ((hour - dt_now.hour + 24) % 24)
    wait_minute = ((minute - dt_now.minute + 59) % 60)
    wait_second = 59 - dt_now.second

    log(f'wait offset: {wait_hour}:{wait_minute}:{wait_second}')
    wait = wait_hour * 60 * 60 + wait_minute * 60 + wait_second

    start = dt_now.timestamp() + wait
    log(f'wait: {wait}, start: {start}, dt_now: {dt_now.timestamp()}, now: {time.time()}')

    atter = Atter(tz)

    reppy = make_exec_repeater(cmd_args, interval)
    atter.add(start, reppy)
    try:
        atter.run()
    except KeyboardInterrupt:
        pass

    return 0


if __name__ == '__main__':

    sys.exit(main())
