import json
import os
import re
import time

import sys
from urllib.error import HTTPError

import requests
from colorama import Fore

from config import config
from config.config import CFG_PATH_FOR_SIGNATURES, URL_FOR_SIGNATURES, CFG_PATH_FOR_RANSOMWARE_FILE_PATTERNS, \
    URL_FOR_RANSOMWARE_FILE_PATTERNS
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
                print(
                    f'{Fore.YELLOW}Timing: elapsed time:{Fore.RESET} %f sec | M: start mem: %f MB delta_mem: %f MB' % (
                        self.secs, self.start_mem, self.delta_mem))
            else:
                print(f'{Fore.YELLOW}Timing: elapsed time:{Fore.RESET} %f sec' % self.secs)


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
    # print(results)

    """
    - match at the start of the string
    - searching for match after the start of the string introduces more FN, so it's better to have FP than negatives ones
    """
    if results and results[0][2] == 0:
        # It returns only the first one
        sig, desc, offset = results[0][0], results[0][1], results[0][2]
        if verbose:
            print(
                f"{Fore.LIGHTBLUE_EX} + filename:{Fore.RESET} '{file}' - sig: '{sig}' - off: {str(offset)} - types: '{desc}'")
        return True, sig, desc, offset

    if verbose:
        print(f"{Fore.LIGHTBLUE_EX} + filename:{Fore.RESET} '{file}'")
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


#  ----------------- RANSOMWARE EXTENSIONS UTILITY ----------------------------------------

def load_ransomware_file_patterns():
    """
    Load Ransomware patterns

    :return:
    """

    def write_file():
        url = URL_FOR_RANSOMWARE_FILE_PATTERNS
        print(f'{Fore.LIGHTCYAN_EX}Fetch the signature file pattern from: {url}')
        response = requests.get(url)
        if response.status_code == 200:
            with open(path, "w") as f:
                json.dump(response.json(), f)

    path = os.path.expanduser(CFG_PATH_FOR_RANSOMWARE_FILE_PATTERNS)

    if os.path.exists(path):
        mtime = os.path.getmtime(path)
        now = time.time()
        diff = (now - mtime) / (24 * 60 * 60)
        if diff > 1:
            write_file()
    else:
        write_file()

    with open(path, 'rt', encoding='utf-8') as f:
        config.RANSOMWARE_FILE_PATTERN = dict()
        for item in json.loads(f.read())['filters']:
            config.RANSOMWARE_FILE_PATTERN[re.sub(r'[\[\]]', "", item)] = item
