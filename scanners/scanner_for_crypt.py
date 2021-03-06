# -*- coding: utf-8 -*-

import os
from pathlib import Path
from typing import Optional

from colorama import Fore

from config import config
from logic.csv_row import CsvRow
from logic.randomness import RandTest
from misc import utils
from scanners.scanner import Scanner

IMAGE = "Image"
CRYPTO = "Crypto"
CRYPTO_NOTPROC = "Ignored"


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
        self.rand = RandTest()

    def print_config(self):
        print(Fore.RESET)
        print(f"{Fore.LIGHTCYAN_EX}{Scanner.sep} Config elements for '{__name__}' {Scanner.sep}")
        print()
        print(
            f'{Fore.YELLOW}Compression Randomness threshold (strictly greater than):{Fore.GREEN} {str(config.CFG_COMPR_RAND_TH)}{Fore.RESET}')
        print(
            f'{Fore.YELLOW}Entropy Randomness threshold (strictly greater than):{Fore.GREEN} {str(config.CFG_ENTR_RAND_TH)}{Fore.RESET}')
        print(
            f'{Fore.YELLOW}Number of first bytes of the content to elaborate:{Fore.GREEN} {"All" if config.CFG_N_BYTES_2_RAND_CHECK is None else str(config.CFG_N_BYTES_2_RAND_CHECK)}{Fore.RESET}')
        print(Fore.RESET)

    def file(self, full_file_path:str):

        self.print_config()
        print(f'{Fore.LIGHTCYAN_EX}{Scanner.sep} Starting search Crypto content in: {str(full_file_path)} {Scanner.sep}')
        print(Fore.RESET)

        super()._internal_file(full_file_path)

    def search(self, path, recursive=True):
        # if self.verbose:
        self.print_config()
        print(f'{Fore.LIGHTCYAN_EX}{Scanner.sep} Starting search Crypto content in: {str(path)} {Scanner.sep}')
        print(Fore.RESET)
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
                        self._process_a_file(f)
                    elif f.is_dir() and recursive:
                        if self.verbose:
                            print(f"{Fore.LIGHTBLUE_EX}+ Searching (for crypto) in the path:{Fore.RESET} '{f.path}'")
                        self._search(f, recursive)

                except PermissionError as e:
                    print(f'EEE => Permissions error: {e}')
                except OSError as e:
                    print(f"EEE(1) => OSError '{e.errno}-{e.strerror}' for: '{f.path}'")

    def _process_a_file(self, file):
        ext = Path(file).suffix.lower().replace('.', '')
        if len(ext) == 0 or ext not in config.EXT_FILES_LIST_TO_EXCLUDE:
            found = self._search_for_crypted_content(file)
            if found:
                print(f'{Fore.RED}---> Crypto analysis result: {Fore.RESET}{found.min_print()}')
                self.found.append(found)

    def _search_for_crypted_content(self, file) -> Optional[CsvRow]:
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
                adesc = None
                is_well_known, sig, desc, offset = utils.is_known_file_type(file.name, content, verbose=self.verbose)
                if not is_well_known:

                    # read the size of the file set in the config
                    handle.seek(0)
                    content = handle.read(config.CFG_N_BYTES_2_RAND_CHECK)
                    lcontent = len(content)

                    rnd_test_entropy = round(RandTest.calc_entropy_test(content, self.verbose), 5)
                    rnd_test_compr = round(self.rand.calc_compression_test(content, self.verbose), 5)
                    adesc = f'entropy: {str(rnd_test_entropy)} OR comp: {rnd_test_compr}'

                    # Tests: entropy || compression factor
                    if (rnd_test_entropy > config.CFG_ENTR_RAND_TH) \
                            or (
                            rnd_test_compr > config.CFG_COMPR_RAND_TH and lcontent > config.CFG_COMPRESSED_CONTENT_MIN_LEN):
                        return CsvRow(file, CRYPTO, adesc)
                    else:
                        if self.verbose:
                            return CsvRow(file, CRYPTO_NOTPROC, f"{adesc} - content length: {lcontent}")
                else:
                    # with verbose flag all the items are put into the outcome to evaluate also the excluded items
                    if self.verbose:
                        return CsvRow(file, CRYPTO_NOTPROC,
                                      f"Well Known filetype - sig: '{sig}', first type recogn: \"{desc}\" <- offset: {str(offset)} - {adesc}")

        except PermissionError:
            print(f"EEE => Permissions error for: '{file.path}'")
        except OSError as e:
            print(f'EEE(2) => OSError {e.errno}-{e}')

        return None
