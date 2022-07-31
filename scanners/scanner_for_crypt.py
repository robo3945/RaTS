# -*- coding: utf-8 -*-

import os
from os.path import getsize
from pathlib import Path
from typing import Optional

from colorama import Fore

from config import config
from logic.csv_manager import CsvRow
from logic.randomness import RandCompressionTest, RandEntropyTest, RandMonobitTest
from misc import utils
from scanners.scanner import Scanner

CRYPTO = "Crypto"
IGNORED = "Ignored"
ERROR = "Error"


class ScannerForCrypt(Scanner):
    """
    Class managing the encrypted file: in the filename and in the content
    """

    def __init__(self, rand_test='all', csv_path=None, verbose=False):
        """
        Initialization
        :return:
        """
        super().__init__(csv_path, verbose)

        self.rand_entropy_test = RandEntropyTest()
        self.rand_compression_test = RandCompressionTest()
        self.rand_monobit_test = RandMonobitTest()
        self.is_entropy = False
        self.is_compression = False
        self.is_monobit = False

        if rand_test == 'entropy':
            self.is_entropy = True
        elif rand_test == 'compression':
            self.is_compression = True
        elif rand_test == 'monobit':
            self.is_monobit = True
        elif rand_test == 'all':
            self.is_compression = True
            self.is_entropy = True
            self.is_monobit = True
        else:
            raise Exception("Crypto argument is needed!")

    def print_config(self):
        print(Fore.RESET)
        print(f"{Fore.LIGHTCYAN_EX}{Scanner.sep} Config elements for '{__name__}' {Scanner.sep}")
        print()
        print(
            f'{Fore.YELLOW}Compression Randomness threshold (strictly greater than):{Fore.GREEN} {str(config.CFG_COMPR_RAND_TH)}{Fore.RESET}')
        print(
            f'{Fore.YELLOW}Entropy Randomness threshold (strictly greater than):{Fore.GREEN} {str(config.CFG_ENTR_RAND_TH)}{Fore.RESET}')
        print(
            f'{Fore.YELLOW}Monobit Randomness threshold (strictly greater than):{Fore.GREEN} {str(config.CFG_MONOBIT_RAND_TH)}{Fore.RESET}')
        print(
            f'{Fore.YELLOW}Number of first bytes of the content to elaborate:{Fore.GREEN} {"All" if config.CFG_N_BYTES_2_RAND_CHECK is None else str(config.CFG_N_BYTES_2_RAND_CHECK)}{Fore.RESET}')
        print(Fore.RESET)

    def file(self, full_file_path: str) -> CsvRow:

        self.print_config()
        print(
            f'{Fore.LIGHTCYAN_EX}{Scanner.sep} Starting search Crypto content in: {str(full_file_path)} {Scanner.sep}')
        print(Fore.RESET)

        return super()._internal_one_file(full_file_path)

    def search(self, path, dirs_to_exclude=None, recursive=True):
        # if self.verbose:
        self.print_config()
        print(f'{Fore.LIGHTCYAN_EX}{Scanner.sep} Starting search Crypto content in: {str(path)} {Scanner.sep}')
        print(Fore.RESET)
        self.csv_manager.print_header()
        self._search(path, dirs_to_exclude, recursive)

    def _search(self, path, dirs_to_exclude=None, recursive=True):
        """
        Recursive main search method
        :param recursive: recursive flag
        :param path: starting path
        :return:
        """

        try:
            for entry in os.scandir(path):
                try:
                    if entry.is_dir(follow_symlinks=False) and recursive:
                        if self.verbose:
                            print(
                                f"{Fore.LIGHTBLUE_EX}+ Searching (for crypto) in the path:{Fore.RESET} '{entry.path}'")
                        if not Scanner.is_excluded_dir(entry.path, dirs_to_exclude):
                            self._search(entry, dirs_to_exclude, recursive)
                    else:
                        self._process_a_file(entry)

                except PermissionError as e:
                    msg = f'EEE (Dir) => Permissions error: {e}'
                    print(msg)
                    if self.verbose:
                        self.csv_manager.csv_row(entry, ERROR, msg)
                except OSError as e:
                    msg = f"EEE(1) (Dir) => OSError '{e.errno}-{e.strerror}' for: '{entry.path}'"
                    print(msg)
                    if self.verbose:
                        self.csv_manager.csv_row(entry, ERROR, msg)
                except UnicodeEncodeError as e:
                    msg = f"EEE (Dir) => Unicode Error for dir entry - defensive strategy to continue: {e}"
                    print(msg)
                    if self.verbose:
                        self.csv_manager.csv_row(entry, ERROR, msg)

        except PermissionError as e:
            msg = f'EEE (ScanDir) => Permission error: {e}'
            print(msg)
        except FileNotFoundError as e:
            msg = f'EEE (ScanDir) => FileNotFound error: {e}'
            print(msg)

    def _process_a_file(self, file) -> CsvRow:
        ext = Path(file).suffix.lower().replace('.', '')
        if len(ext) == 0 or ext not in config.EXT_FILES_LIST_TO_EXCLUDE:
            found = self._search_for_crypted_content(file)
            if found:
                print(f'{Fore.RED}---> Crypto result: {Fore.RESET}{found.min_print()}')
                return found

    def _search_for_crypted_content(self, file) -> Optional[CsvRow]:
        """
        Calculate randomness of the crypto content

        :param file:
        :return:
        """
        try:
            # check for the thresholds
            file_size = getsize(file.path)

            # treshold test for the entropy (min length)
            if file_size < config.CFG_RAND_CONTENT_MIN_LEN:
                if self.verbose:
                    self.csv_manager.csv_row(file, IGNORED,
                                                    f"[rand test] content length: {file_size} < {config.CFG_RAND_CONTENT_MIN_LEN}")
                return None

            with open(file=file.path, mode='rb') as handle:

                # read only the first part of the file to check the magic type
                content = handle.read(config.CFG_MAX_FILE_SIGNATURE_LENGTH)
                if len(content) == 0:
                    return None

                # well known file are not checked
                is_well_known, sig, desc, offset = utils.is_known_file_type(file.name, content, verbose=self.verbose)
                if not is_well_known:

                    # read the size of the file set in the config
                    handle.seek(0)
                    content = handle.read(config.CFG_N_BYTES_2_RAND_CHECK)

                    message = "[rand test] true "
                    is_found = False
                    # test for the compression test: TRUE RANDOMNESS, slow computation
                    if self.is_compression:
                        if (rnd_test_compr := self.rand_compression_test.calc_rand_idx(content,
                                                                                       False)) > config.CFG_COMPR_RAND_TH:
                            message += f'&& COMPRESSION: {rnd_test_compr} > {config.CFG_COMPR_RAND_TH} '
                            is_found = True
                        else:
                            message += f'&& !compression: {rnd_test_compr} > {config.CFG_COMPR_RAND_TH} '

                    # test for the entropy: QUANTITY OF INFORMATION -> ENTROPY OF THE SOURCE NOT THE MESSAGE, normal speed
                    if self.is_entropy:
                        if (rnd_test_entropy := self.rand_entropy_test.calc_rand_idx(
                                content)) > config.CFG_ENTR_RAND_TH:
                            message += f'&& ENTROPY: {rnd_test_entropy} > {config.CFG_ENTR_RAND_TH} '
                            is_found = True
                        else:
                            message += f'&& !entropy: {rnd_test_entropy} > {config.CFG_ENTR_RAND_TH} '

                    # test for randomness from the RAND TEST OF NIST: WEAK TEST but very fast
                    if self.is_monobit:
                        if (rand_test_monobit := self.rand_monobit_test.calc_rand_idx(
                                content)) > config.CFG_MONOBIT_RAND_TH:
                            message += f'&& MONOBIT: {rand_test_monobit} > {config.CFG_MONOBIT_RAND_TH}'
                            is_found = True
                        else:
                            message += f'&& !monobit: {rand_test_monobit} > {config.CFG_MONOBIT_RAND_TH}'

                    if is_found:
                        return self.csv_manager.csv_row(file, CRYPTO, message)
                    else:
                        if self.verbose:
                            self.csv_manager.csv_row(file, IGNORED, message)

                else:
                    # with verbose flag all the items are put into the outcome to evaluate also the excluded items
                    if self.verbose:
                        self.csv_manager.csv_row(file, IGNORED,
                                                        f"Well known filetype - sig: '{sig}' - off: {str(offset)} - types: \"{desc}\"")

        except PermissionError:
            msg = f"EEE => Permissions error for: '{file.path}'"
            print(msg)
            if self.verbose:
                self.csv_manager.csv_row(file, ERROR, msg)
        except OSError as e:
            msg = f'EEE(2) => OSError {e.errno}-{e}'
            print(msg)
            if self.verbose:
                self.csv_manager.csv_row(file, ERROR, msg)

        return None