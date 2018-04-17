# -*- coding: utf-8 -*-

"""
RaTS: Ransomware Traces Scanner
Copyright (C) 2015, 2016, 2017, 2018 Roberto Battistoni (r.battistoni@gmail.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

import os
import time

import sys
from urllib.error import HTTPError

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
                print('##T: elapsed time: %f sec | M: start mem: %f MB delta_mem: %f MB' % (
                    self.secs, self.start_mem, self.delta_mem))
            else:
                print('##T: elapsed time: %f sec' % self.secs)


#  ----------------- SIGNATURES UTILITY ----------------------------------------

def is_known_file_type(content, verbose: bool = False) -> bool:
    """
    Check if the file has a compressed file signature
    :param content:
    :param verbose:
    :return:
    """

    results = check_sig_content(content, signatures)

    if results and results[0][2] == 0:
        # It returns only the first one

        # commented for performance improvement
        #if verbose:
        #    sig, desc, offset = results[0][0], results[0][1], results[0][2]
        #    print(f"[+] {sig} : First type recogn. \"{desc}\" <- Offset: {str(offset)}")
        return True

    return False


def _check_compile_sigs():
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


# builds the signatures (only the first time)
signatures = _check_compile_sigs()