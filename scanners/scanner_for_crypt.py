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

import gzip
import hashlib
import imghdr
from pathlib import Path
from config import config
from misc import utils
from scanners.csv_row import CsvRow
from scanners.scanner import Scanner

IMAGE = "Image"
CRYPTO = "Crypto"


class ScannerForCrypt(Scanner):
    """
    Class managing the encrypted file: in the filename and in the content
    """

    __b0 = str("").encode("utf-8")
    __c0 = gzip.compress(__b0)
    __l0 = len(__c0)

    def __init__(self, verbose=False):
        """
        Initialization
        :return:
        """
        super().__init__(verbose)

    def print_config(self):
        print("%s Config elements for '%s' %s" % (Scanner.sep, __name__, Scanner.sep))
        print()
        print("Randomness threshold (strictly greater than): " + str(config.randomness_threshold))
        print("Number of first bytes of the content to elaborate: " + str(config.rand_first_n_bytes_to_check))
        print()

    def search(self, path, recursive=True):
        """
        The main search method

        :param path:
        :param recursive:
        :return:
        """
        if self.verbose:
            self.print_config()
        print(Scanner.sep + " Starting search Crypto content in: " + str(path) + " " + Scanner.sep)
        self._search(path, recursive)

    def _search(self, path, recursive=True):
        """
        Recursive main search method
        :param recursive: recursive flag
        :param path: starting path
        :return:
        """
        p = Path(path)

        try:
            file_list = [x for x in p.iterdir() if not x.is_symlink() and x.is_file()]
            for f in file_list:
                if self.verbose:
                    print("- Searching for crypto content in the file: " + str(f))
                found = self.search_for_crypted_content(f)
                if found:
                    print("=====> Found crypto content in: " + str(f))
                    self.found.append(found)

            if recursive:
                dir_list = [x for x in p.iterdir() if not x.is_symlink() and x.is_dir()]
                for x in dir_list:
                    if self.verbose:
                        print("+ Searching (for crypto) in the path: " + str(x))
                    self._search(x, recursive)

        except PermissionError:
            print("EEE => Permissions error for: " + str(p))
        except OSError as e:
            print("EEE => OSError: " + e.strerror)

    def search_for_crypted_content(self, file):
        """
        Calculate randomness of the crypto content

        :param file:
        :return:
        """
        try:
            with file.open(mode='rb') as handle:
                content = handle.read(config.rand_first_n_bytes_to_check)

                # for the empty files
                if len(content) == 0:
                    return None

                sha1 = hashlib.sha1(content).hexdigest()
                rnd = self.calc_randomness(content)
                if rnd and rnd > config.randomness_threshold:

                    # Localizable
                    rnd = str(rnd * 100).replace('.', ',')

                    # default is crypto
                    file_type = CRYPTO
                    # if compressed and image then it's not random data
                    if imghdr.what(file, h=content):
                        file_type = IMAGE
                    else:
                        # magic bytes to identify compressed content
                        ret = utils.is_compressed_file(content)
                        file_type = ret if ret else file_type

                    return CsvRow(file, file_type, rnd, sha1)

        except PermissionError:
            print("EEE => Permissions error for: " + str(file))
        except OSError as e:
            print("EEE => OSError: " + e.strerror)

        return None

    def calc_randomness(self, bcontent):
        """
        Calculates the randomness of the content using the Kolmogorov complexity

        It's a practical manner we compress the content and evaluate the grade of the compression:
        - lesser the compression is, higher the randomness is
        - len(zipped)/len(content)
        :param bcontent:
        :return:
        """

        # if print_path:
        #    print("The content is: %s" % content)
        d = len(bcontent)
        if d == 0:
            if self.verbose:
                print("Empty string, nothing to do!")
            return None

        c = gzip.compress(bcontent, 9)
        # deleting the footprint for the compression
        n = (len(c) - ScannerForCrypt.__l0) * 1.0
        randomness = n / d

        if self.verbose:
            print("-> crypto values: n: %s, d: %s, l0: %s, rand ratio: %s " % (n, d, ScannerForCrypt.__l0, randomness))

        return randomness
