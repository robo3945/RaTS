# -*- coding: utf-8 -*-

import os
from pathlib import Path
from typing import Optional

from colorama import Fore

from config import config
from logic.csv_manager import CsvRow
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

    def __init__(self, csv_path = None, verbose=False):
        """
        Initialization
        :return:
        """
        super().__init__(csv_path, verbose)
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

    def file(self, full_file_path: str) -> CsvRow:

        self.print_config()
        print(
            f'{Fore.LIGHTCYAN_EX}{Scanner.sep} Starting search Crypto content in: {str(full_file_path)} {Scanner.sep}')
        print(Fore.RESET)

        return super()._internal_file(full_file_path)

    def search(self, path, recursive=True):
        # if self.verbose:
        self.print_config()
        print(f'{Fore.LIGHTCYAN_EX}{Scanner.sep} Starting search Crypto content in: {str(path)} {Scanner.sep}')
        print(Fore.RESET)
        self.csv_manager.print_header()
        self._search(path, recursive)

    def _search(self, path, recursive=True):
        """
        Recursive main search method
        :param recursive: recursive flag
        :param path: starting path
        :return:
        """

        for entry in os.scandir(path):
            try:
                try:
                    if entry.is_dir(follow_symlinks=False) and recursive:
                        if self.verbose:
                            print(f"{Fore.LIGHTBLUE_EX}+ Searching (for crypto) in the path:{Fore.RESET} '{entry.path}'")
                        self._search(entry, recursive)
                    else:
                        self._process_a_file(entry)

                except PermissionError as e:
                    print(f'EEE => Permissions error: {e}')
                except OSError as e:
                    print(f"EEE(1) => OSError '{e.errno}-{e.strerror}' for: '{entry.path}'")

            except UnicodeEncodeError as e:
                print(f"EEE => Unicode Error for file - defensive strategy to continue: {e}")


    def _process_a_file(self, file) -> CsvRow:
        ext = Path(file).suffix.lower().replace('.', '')
        if len(ext) == 0 or ext not in config.EXT_FILES_LIST_TO_EXCLUDE:
            found = self._search_for_crypted_content(file)
            if found:
                print(f'{Fore.RED}---> Crypto analysis result: {Fore.RESET}{found.min_print()}')
                # TODO to remove
                #self.found.append(found)
                return found

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

                    # treshold test for the entropy (min length)
                    if self.verbose and lcontent < config.CFG_ENTROPY_CONTENT_MIN_LEN:
                        return self.csv_manager.csv_row(file, CRYPTO_NOTPROC, f"[entropy] content length: {lcontent} < {config.CFG_ENTROPY_CONTENT_MIN_LEN}")

                    # treshold test for the compression test (min length)
                    if self.verbose and lcontent < config.CFG_COMPRESSED_CONTENT_MIN_LEN:
                        return self.csv_manager.csv_row(file, CRYPTO_NOTPROC, f"[compression] content length: {lcontent} < {config.CFG_COMPRESSED_CONTENT_MIN_LEN}")

                    # test for the entropy
                    if (rnd_test_entropy := RandTest.calc_entropy_test(content, self.verbose)) > config.CFG_ENTR_RAND_TH:
                        return self.csv_manager.csv_row(file, CRYPTO, f'[randomness test] 1-entropy: {rnd_test_entropy} > {config.CFG_ENTR_RAND_TH}')

                    # test for the compression test
                    if (rnd_test_compr := self.rand.calc_compression_test(content, self.verbose)) > config.CFG_COMPR_RAND_TH:
                        return self.csv_manager.csv_row(file, CRYPTO, f'[randomness test] 2-compression: {rnd_test_compr} > {config.CFG_COMPR_RAND_TH}')

                else:
                    # with verbose flag all the items are put into the outcome to evaluate also the excluded items
                    if self.verbose:
                        return self.csv_manager.csv_row(file, CRYPTO_NOTPROC,
                                      f"Well Known filetype - sig: '{sig}', first type recogn: \"{desc}\" <- offset: {str(offset)} - {adesc}")

        except PermissionError:
            print(f"EEE => Permissions error for: '{file.path}'")
        except OSError as e:
            print(f'EEE(2) => OSError {e.errno}-{e}')

        return None
