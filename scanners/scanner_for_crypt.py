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
import os
from pathlib import Path
from typing import Optional

from config import config
from logic.csv_row import CsvRow
from logic.randomness import RandTest
from misc import utils
from scanners.scanner import Scanner

IMAGE = "Image"
CRYPTO = "Crypto"
CRYPTO_NOTPROC = "NotProcessed"


class ScannerForCrypt(Scanner):
    """
    Class managing the encrypted file: in the filename and in the content
    """

    def __init__(self, verbose=False):
        """
        Initialization
        :return:
        """
        super().__init__(verbose)

    def print_config(self):
        print(f'{Scanner.sep} Config elements for \"{__name__}\" {Scanner.sep}')
        print()
        print(
            f'Compression Randomness threshold (strictly greater than): {str(config.CFG_COMPR_RAND_TH)}')
        print(f'Entropy Randomness threshold (strictly greater than): {str(config.CFG_ENTR_RAND_TH)}')
        print(f'Number of first bytes of the content to elaborate: {str(config.CFG_N_BYTES_2_RAND_CHECK)}')
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
        print(f'{Scanner.sep} Starting search Crypto content in: {str(path)} {Scanner.sep}')
        self._search(path, recursive)

    def _search(self, path, recursive=True):
        """
        Recursive main search method
        :param recursive: recursive flag
        :param path: starting path
        :return:
        """
        with os.scandir(path) as it:
            for f in it:
                try:
                    if f.is_file() and not f.is_symlink() and not f.name.startswith('.'):
                        ext = Path(f).suffix.lower().replace('.', '')
                        if ext not in config.EXT_FILES_LIST_TO_EXCLUDE:
                            found = self.search_for_crypted_content(f)
                            if found:
                                print(f'===> Possible encrypted content analysed: {found}')
                                self.found.append(found)

                    elif f.is_dir() and recursive:
                        if self.verbose:
                            print(f'+ Searching (for crypto) in the path: {f.path}')
                        self._search(f, recursive)

                except PermissionError as e:
                    print(f'EEE => Permissions error: {e}')
                except OSError as e:
                    print(f'EEE(1) => OSError "{e.errno}-{e.strerror}" for: {f.path}')

    def search_for_crypted_content(self, file) -> Optional[CsvRow]:
        """
        Calculate randomness of the crypto content

        :param file:
        :return:
        """
        try:
            with open(file=file.path, mode='rb') as handle:
                # read only the first part of the file to check the magic type
                content = handle.read(config.CFG_MAX_FILE_SIGNATURE_LENGTH)
                if len(content) == 0:
                    return None

                # well known file are not checked
                ret, sig, desc, offset = utils.is_known_file_type(file.name, content, verbose=self.verbose)
                if not ret:

                    # read the size of the file set in the config
                    content = handle.read(config.CFG_N_BYTES_2_RAND_CHECK)
                    lcontent = len(content)

                    # First test: entropy
                    rnd_test_entropy = round(RandTest.calc_entropy_test(content, self.verbose), 2)
                    if rnd_test_entropy > config.CFG_ENTR_RAND_TH:

                        # Second test: compression factor
                        rnd_test_compr = round(RandTest.calc_compression_test(content, self.verbose), 2)
                        if rnd_test_compr > config.CFG_COMPR_RAND_TH and lcontent > config.CFG_COMPRESSED_CONTENT_MIN_LEN:
                            adesc = f'Entropy: {str(rnd_test_entropy)} && Comp_Fact: {rnd_test_compr}'
                            return CsvRow(file, CRYPTO, adesc)
                else:
                    adesc = f"sig: '{sig}' : first type recogn. \"{desc}\" <- offset: {str(offset)}"
                    return CsvRow(file, CRYPTO_NOTPROC, adesc)

        except PermissionError as e:
            print(f'EEE => Permissions error for: {file.path}')
        except OSError as e:
            print(f'EEE(2) => OSError {e.errno}-{e}')

        return None
