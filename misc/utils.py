# -*- coding: utf-8 -*-

"""
RaTS: Ransomware Traces Scanner
Copyright (C) 2015, 2016 Roberto Battistoni (r.battistoni@gmail.com)

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

import time

from config import config

try:
    import resource
except ImportError:
    pass


def get_mem():
    res = 0
    try:
        res = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) / 1000000
    except NameError:
        pass

    return res


def print_mem_usage(s):
    try:
        print('>>>>: %s-MEM use: %s (MB)' % (s, get_mem()))
    except NameError:
        print('"Resource" package is not available on Windows')
        pass

        # TODO missing the mem check for Windows platform
        # http://code.activestate.com/recipes/511491/


def is_compressed_file(content):
    """
    Check if the file has a compressed file signature
    :param content:
    :return:
    """

    for s in config.compressed_signatures:
        found = True
        for i in range(len(s[1])):
            if s[1][i] != content[i]:
                found = False
                break

        if found:
            return s[0]

    return None


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
