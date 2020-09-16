# -*- coding: utf-8 -*-

"""
RaTS: Ransomware Traces Scanner
Copyright (C) 2015 -> 2020 Roberto Battistoni (r.battistoni@gmail.com)

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

import gzip
from collections import Counter

import math


class RandTest:
    @staticmethod
    def calc_entropy_test(content: bytes, verbose: bool) -> float:
        """
        Entropy randomness test
        :param content:
        :param verbose:
        :return:
        """

        def entropy(content) -> float:
            """
            Binary Entropy from: http://rosettacode.org/wiki/Entropy#Python:_More_succinct_version
            :param content: content (string or byte array)
            :return:
            """
            p, lns = Counter(content), float(len(content))
            return -sum(count / lns * math.log(count / lns, 2) for count in p.values())

        H = entropy(content)

        if verbose:
            print("-> [Entropy Test] crypto values: H: %s" % H)

        return H

    @staticmethod
    def calc_compression_test(bcontent: bytes, verbose: bool) -> float:
        """
        Calculates the randomness of the content using the Kolmogorov complexity

        We compress the content and evaluate the grade of the compression:
        - lesser the compression is, higher the randomness is: len(zipped)/len(content)
        - upperbound for randomness is 1, lowerbound is > 0
        - upperbound for compression is > 0, lowerbound is 1

        :param bcontent: byte content
        :param verbose:
        :return: [0,1]
        """

        def compress(data):
            return gzip.compress(data, 9)

        def get_compressed_footprint():
            return len(compress(bytes([0x0])))

        # if print_path:
        #    print("The content is: %s" % content)
        len_bcontent = len(bcontent)
        if len_bcontent == 0:
            if verbose:
                print("Empty string, nothing to do!")
            return 0

        len_compr_cnt = len(compress(bcontent))
        # deleting the footprint for the compression
        len_compr_cnt_1 = (len_compr_cnt - get_compressed_footprint()) * 1.0
        rand = len_compr_cnt_1 / len_bcontent

        if verbose:
            print("-> [Compression Test] crypto values: n: %s, d: %s, l0: %s, rand ratio: %s " % (
                len_compr_cnt_1, len_bcontent, get_compressed_footprint(), rand))

        return rand
