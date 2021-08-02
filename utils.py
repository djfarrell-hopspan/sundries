
import os


log = print


def safe_remove(fname):

    try:
        os.remove(fname)
    except IOError as e:
        log(f'error: rm: {e}')
    except OSError as e:
        log(f'error: rm: {e}')
    except Exception as e:
        log(f'error: rm: {e}')
