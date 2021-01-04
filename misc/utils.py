# -*- coding: utf-8 -*-

import os
import time

import sys
from urllib.error import HTTPError

from config import config
from config.config import CFG_PATH_FOR_SIGNATURES, URL_FOR_SIGNATURES
from logic.check_sigs import compile_sigs, check_sig_content

try:
    import resource
except ImportError:
    pass


def norm_percentage(f: float) -> str:
    """
    Normalize float in [0,1] to xxx% number with comma replacing dots
    :param f:
    :return:
    """
    return str(f * 100).replace('.', ',')


def get_mem():
    res = 0
    try:
        res = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1000000
    except NameError:
        pass

    return res


def print_mem_usage(s):
    try:
        print('>>>>: %s-MEM use: %s (MB)' % (s, get_mem()))
    except NameError:
        print('"Resource" package is not available on Windows')
        pass


def check_configuration():
    """
    Check the configuration for duplicate items and other inconsistencies
    :return:
    """
    # TODO: check the configuration
    pass


class Timer(object):
    def __init__(self, verbose=False, mem=False):
        self.mem = mem
        self.verbose = verbose

    def __enter__(self):
        self.start = time.time()
        if self.mem:
            self.start_mem = get_mem()
        return self

    def __exit__(self, *args):
        self.end = time.time()
        if self.mem:
            self.end_mem = get_mem()
            self.delta_mem = self.end_mem - self.start_mem

        self.secs = self.end - self.start
        self.msecs = self.secs * 1000  # millisecs
        if self.verbose:
            if self.mem:
                print('#Timing: elapsed time: %f sec | M: start mem: %f MB delta_mem: %f MB' % (
                    self.secs, self.start_mem, self.delta_mem))
            else:
                print('#Timing: elapsed time: %f sec' % self.secs)


#  ----------------- SIGNATURES UTILITY ----------------------------------------

def is_known_file_type(file, content, verbose: bool = False):
    """
    Check if the file has a compressed file signature
    :param file: the filename
    :param content: the content to analyze
    :param verbose:
    :return:
    """

    results = check_sig_content(content, config.signatures)

    if results and results[0][2] == 0:
        # It returns only the first one
        sig, desc, offset = results[0][0], results[0][1], results[0][2]
        if verbose:
            print(f"[+] filename: '{file}' - sig: '{sig}' : First type recogn. '{desc}' <- Offset: {str(offset)}")
        return True, sig, desc, offset

    if verbose:
        print(f"[+] filename: '{file}'")
    return False, None, None, None


def check_compile_sigs():
    path = os.path.expanduser(CFG_PATH_FOR_SIGNATURES)
    url = URL_FOR_SIGNATURES
    try:
        signs = compile_sigs(path, url)
    except HTTPError as err:
        if err.code == 404:
            print(
                "File Signatures web site is not available. I am not able to dynamically recreate the file. Please drop a signatures file in the application directory.")
            sys.exit()
        else:
            raise
    return signs
