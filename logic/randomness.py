# -*- coding: utf-8 -*-

import gzip
from collections import Counter

import math


class RandTest:
    """
    Class for randomness tests
    """

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
    def _compress(data) -> bytes:
        return gzip.compress(data, 9)

    def __init__(self):
        self._compression_footprint_length = len(RandTest._compress(bytes([0x0])))

    def calc_compression_test(self, bcontent: bytes, verbose: bool) -> float:
        """
        Calculates the randomness of the content using the Kolmogorov complexity

        - more is the compression/randomness, lesser the randomness/compression is
        - def: ratio = len(zipped_content)/len(content)
        -   ratio close to 1 means high randomness and low compression
        -   ratio close to 0 means high compression and low randomness

        :param bcontent: byte content
        :param verbose:
        :return: [0,1]
        """

        # if print_path:
        #    print("The content is: %s" % content)
        len_bcontent = len(bcontent)
        if len_bcontent == 0:
            if verbose:
                print("Empty string, nothing to do!")
            return 0

        len_compr_cnt = (len(self._compress(bcontent)) - self._compression_footprint_length) * 1.0
        rand = len_compr_cnt / len_bcontent

        if verbose:
            print("-> [Compression Test] crypto values: n: %s, d: %s, l0: %s, rand ratio: %s " % (
                len_compr_cnt, len_bcontent, self._compression_footprint_length, rand))

        return rand
