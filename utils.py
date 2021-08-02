
import os


log = print
logw = print
loge = print
logd = print


def safe_remove(fname):

    try:
        os.remove(fname)
    except IOError as e:
        loge(f'error: rm: {e}')
    except OSError as e:
        loge(f'error: rm: {e}')
    except Exception as e:
        loge(f'error: rm: {e}')
