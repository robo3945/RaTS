# -*- coding: utf-8 -*-

import os
import re
from operator import itemgetter
from pathlib import Path
from typing import Optional

from config import config
from logic.csv_row import CsvRow
from misc import utils
from scanners.scanner import Scanner

IGNORED_FILE = "Ignored file"


class ScannerForFile(Scanner):
    """
    The search main class
    """

    def __init__(self, verbose=False):
        """
        Initialization of the fields
        :return:
        """
        super().__init__(verbose)
        self.file_bad_exts_set = set([line.strip().lower() for line in config.FILE_BAS_EXTS.split(",") if
                                      line.strip() != ""])
        self.file_name_terms_set = set([line.strip().lower() for line in config.MANIFEST_FILE_NAME_TERMS.split(",") if
                                        line.strip() != ""])
        self.file_name_exts_set = set([line.strip().lower() for line in config.CFG_FILE_NAME_EXTS.split(",") if
                                       line.strip() != ""])
        self.file_text_terms_set = set(sorted(config.FILE_TEXT_TERMS_DIC, key=itemgetter(1), reverse=True))

    def print_config(self):
        """
        Print the values of the configuration
        :return:
        """
        print(f'{Scanner.sep} Config elements for "{__name__}" {Scanner.sep}')
        print()
        print(f'Bad file extensions detected: {str(self.file_bad_exts_set)}')
        print(f'File extensions analyzed: {str(self.file_name_exts_set)}')
        print(f'File names detected (without the extensions): {str(self.file_name_terms_set)}')
        print(f'List with terms and their "relevance": {str(self.file_text_terms_set)}')
        print()

    def search(self, path, recursive=True):
        """
        The main search method

        :param path:
        :param recursive:
        :return:
        """

        # if self.verbose:
        self.print_config()
        print(f'{Scanner.sep} Starting search Ransomware manifest traces in: {str(path)} {Scanner.sep}')
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
                        if len(ext) == 0 or ext not in config.EXT_FILES_LIST_TO_EXCLUDE:
                            found = self.__search_in_file(f)
                            if found:
                                print(f'---> Filename analysed: {f.path}')
                                self.found.append(found)

                    elif f.is_dir() and recursive:
                        if self.verbose:
                            print(f"+ Searching in the path: '{f.path}'")
                        self._search(f, recursive)

                except PermissionError as e:
                    print(f'EEE => Permissions error: {e}')
                except OSError as e:
                    print(f'EEE => OSError {e.errno}-{e}')

    def __search_in_file(self, file) -> Optional[CsvRow]:
        """
        The search for the file

        It searches for:

        1)  If the file has a Bad extension
        2)  For the allowed extensions allowed (not the Bad exts), if it has a file name with suspect name part or terms
            in the content. If yes it detect it and continue on the next file

        :param file: the file analyzed
        :return: None or the file detected
        """

        csv_row = None
        ext = Path(file).suffix.lower()
        # check only the files with the max size in the configuration
        if file.stat().st_size <= config.CFG_MANIFEST_MAX_SIZE:
            # check if the file has a bad extension
            if ext in self.file_bad_exts_set:
                if self.verbose:
                    print(f'-> Found bad extension for the file: {ext}')
                csv_row = CsvRow(file, "Bad filename extension", f"extension: {ext}")
            # Only the allowed extensions in the config are checked for the file name and the content
            elif ext in self.file_name_exts_set:
                if self.verbose:
                    print(f"-> Processing the file '{file.path}' for the extension '{ext}'")
                csv_row = self._search_in_file_name(file)
                if not csv_row:
                    if self.verbose:
                        print(f"-> Processing the file '{file.path}' for the content")
                    csv_row = self._search_in_file_content(file)
            else:
                if self.verbose:
                    csv_row = CsvRow(file, IGNORED_FILE, f"File size < {config.CFG_MANIFEST_MAX_SIZE}")
        else:
            if self.verbose:
                csv_row = CsvRow(file, IGNORED_FILE, f"File size > {config.CFG_MANIFEST_MAX_SIZE}")

        return csv_row

    def _search_in_file_name(self, file) -> Optional[CsvRow]:
        """
        Search the match for the file name
        :param file:
        :return:
        """
        lfile = Path(file).stem.lower()
        for f in self.file_name_terms_set:
            if lfile.startswith(f):
                if self.verbose:
                    print(f"--> Found a file name starting with: '{f}'")
                return CsvRow(file, "Bad filename prefix", f"file_name_start_with: '{f}'")

        return None

    def _search_in_file_content(self, file) -> Optional[CsvRow]:
        """
        Search for terms in the file content
        :param file:
        :return:
        """
        try:

            # Test if the file is a well known binary, in this case it skips the content analysis
            with open(file=file.path, mode='rb') as handle:
                # read only the first part of the file to check the magic type
                content = handle.read(config.CFG_MAX_FILE_SIGNATURE_LENGTH)
                if len(content) == 0:
                    return None

                # well known file are not checked
                adesc = None
                is_well_known, sig, desc, offset = utils.is_known_file_type(file.name, content, verbose=self.verbose)

            if is_well_known:
                if self.verbose:
                    return CsvRow(file, IGNORED_FILE,
                                  f"Well Known filetype - sig: '{sig}', first type recogn: \"{desc}\" <- offset: {str(offset)} - {adesc}")

                return None

            else:

                with open(file.path, mode='r', errors='ignore') as handle:
                    content = handle.read()

                    perc, list_found = 0, []
                    for k, v in self.file_text_terms_set:
                        found = re.search(k, content, re.IGNORECASE | re.MULTILINE)
                        if found:
                            list_found.append((k, v))
                            perc += v
                            if perc >= config.CFG_TERM_PERC_TH:
                                if self.verbose:
                                    print(f"--> Found patterns in the file content: '{str(list_found)}'")
                                return CsvRow(file, "ptrn_in_file_content", f'\"{str(list_found)}\"')

        except PermissionError as e:
            print(f'EEE => Permissions error: {e}')
        except OSError as e:
            print(f'EEE => OSError: {e.errno}-{e}')

        return None
