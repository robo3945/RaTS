# -*- coding: utf-8 -*-

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

        - more is the compression/randomness, lesser the randomness/compression is
        - def: ratio = len(zipped_content)/len(content)
        -   ratio close to 1 means high randomness and low compression
        -   ratio close to 0 means high compression and low randomness

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
