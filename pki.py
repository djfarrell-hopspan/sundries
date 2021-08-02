
import functools
import hashlib
import hmac
import os
import shlex
import subprocess
import tempfile

import utils


log =  functools.partial(print, 'info   :')
logw = functools.partial(print, 'warning:')
loge = functools.partial(print, 'error  :')
logd = functools.partial(print, 'debug  :')


def sign(name, data):

    signature = None
    if isinstance(data, str):
        data = data.encode()

    try:
        with subprocess.Popen(['openssl', 'dgst', '-sha256', '-sign', f'{name}_private.pem'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as signer:
            signer.stdin.write(data)
            signer.stdin.close()
            signature = signer.stdout.read()
            signer.wait(timeout=1.)
    except subprocess.TimeoutExpired as e:
        loge(f'error error: {e}')
    except Exception as e:
        loge(f'signer error: {e}')

    return signature


def verify(name, signature, data):

    verified = False
    if isinstance(data, str):
        data = data.encode()

    verifier_out = '(none)'
    with tempfile.NamedTemporaryFile(mode='wb', buffering=0) as sig_file:
        try:
            sig_file.write(signature)
            sig_file.seek(0)
        except Exception as e:
            loge(f'tempfile error: {e}')
        try:
            with subprocess.Popen(['openssl', 'dgst', '-sha256', '-verify', f'{name}_public.pem', '-binary', '-signature', f'{sig_file.name}'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as verifier:
                verifier.stdin.write(data)
                verifier.stdin.close()
                verifier_out = verifier.stdout.read()
                verifier.wait(timeout=1.)
                verified = verifier.returncode == 0
        except subprocess.TimeoutExpired as e:
            loge(f'verifier error: {e}: {verifier_out}')
        except Exception as e:
            loge(f'verifier error: {e}: {verifier_out}')

    return verified


def make_temporal_me_to_them(me_name, them_name):

    private_name = f'{me_name}_{them_name}_private.pem'
    public_name = f'{me_name}_{them_name}_public.pem'
    ret = None

    utils.safe_remove(private_name)
    utils.safe_remove(public_name)

    try:
        subprocess.check_call(shlex.split(f'openssl ecparam -genkey -name secp384r1 -noout -out {private_name}'))
        subprocess.check_call(shlex.split(f'openssl ec -in {private_name} -pubout -out {public_name}'))
        ret = open(f'{me_name}_{them_name}_public.pem', 'rb').read()
        if isinstance(ret, str):
            ret = ret.encode()
    except subprocess.CalledProcessError as e:
        loge(f'making temporal key error: {e}')
    except Exception as e:
        loge(f'making temporal key error: {e}')

    return ret


def save_them_to_me_temporal(them_name, me_name, data):

    fname = f'{them_name}_{me_name}_public.pem'
    with open(fname, 'wb') as outf:
        if isinstance(data, str):
            data = data.encode()
        outf.write(data)

    return True


def derive_temporal_key(them_name, me_name):

    me_to_them_fname = f'{me_name}_{them_name}_private.pem'
    them_to_me_fname = f'{them_name}_{me_name}_public.pem'
    #them_and_me_shared_fname = f'{them_name}_{me_name}_shared.key'

    shell = f'openssl pkeyutl -derive -inkey {me_to_them_fname} -peerkey {them_to_me_fname}'

    deriver_out = None
    try:
        with subprocess.Popen(shlex.split(shell), stdin=subprocess.PIPE, stdout=subprocess.PIPE) as deriver:
            deriver.stdin.close()
            deriver_out = deriver.stdout.read()
            deriver.wait(timeout=1.)
            deriver = deriver.returncode == 0
    except subprocess.TimeoutExpired as e:
        loge(f'deriver error: {e}: {deriver_out}')
        deriver_out = None
    except Exception as e:
        loge(f'deriver error: {e}: {deriver_out}')
        deriver_out = None

    return deriver_out


def calc_hmac(key, data):

    if isinstance(key, str):
        key = key.encode()

    if isinstance(data, str):
        data = data.encode()

    digest = hmac.new(key, data, hashlib.sha256).hexdigest()
    if isinstance(digest, str):
        digest = digest.encode()

    return digest


def verify_hmac(key, data, signature):

    calced = calc_hmac(key, data)

    return calced == signature
