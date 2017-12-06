# -*- coding: utf-8 -*-

"""
RaTS: Ransomware Traces Scanner
Copyright (C) 2015, 2016, 2017, 2018 Roberto Battistoni (r.battistoni@gmail.com)

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

import re
from operator import itemgetter
from pathlib import Path
from typing import Optional

from config import config
from logic.csv_row import CsvRow
from scanners.scanner import Scanner


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
        self.list_file_bad_exts = [line.strip().lower() for line in config.FILE_BAS_EXTS.split(",") if
                                   line.strip() != ""]
        self.list_file_name_terms = [line.strip().lower() for line in config.MANIFEST_FILE_NAME_TERMS.split(",") if
                                     line.strip() != ""]
        self.list_file_name_exts = [line.strip().lower() for line in config.CFG_FILE_NAME_EXTS.split(",") if
                                    line.strip() != ""]
        self.list_file_text_terms = sorted(config.FILE_TEXT_TERMS_DIC, key=itemgetter(1), reverse=True)

    def print_config(self):
        """
        Print the values of the configuration
        :return:
        """
        print(f'{Scanner.sep} Config elements for "{__name__}" {Scanner.sep}')
        print()
        print(f'Bad file extensions detected: {str(self.list_file_bad_exts)}')
        print(f'File extensions analyzed: {str(self.list_file_name_exts)}')
        print(f'File names detected (without the extensions): {str(self.list_file_name_terms)}')
        print(f'List with terms and their "relevance": {str(self.list_file_text_terms)}')
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
        print(f'{Scanner.sep} Starting search Ransomware manifest traces in: {str(path)} {Scanner.sep}')
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
                    print(f'- Processing the file: {str(f)}')
                found = self.__search_in_file(f)
                if found:
                    print(f'=====> Found matches in: {str(f)}')
                    self.found.append(found)

            if recursive:
                dir_list = [x for x in p.iterdir() if not x.is_symlink() and x.is_dir()]
                for x in dir_list:
                    if self.verbose:
                        print(f'+ Searching in the path: {str(x)}')
                    self._search(x, recursive)
        except PermissionError:
            print(f'EEE => Permissions error for: {str(p)}')
        except OSError as e:
            print(f'EEE => OSError: {e.strerror}')

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

        res = None

        # check only the files with the max size in the configuration
        if file.stat().st_size <= config.CFG_MANIFEST_MAX_SIZE:

            # check if the file has a bad extension
            ext = file.suffix.lower()
            if ext in self.list_file_bad_exts:
                if self.verbose:
                    print(f'-> Found bad extension in the file: {str(ext)}')
                res = CsvRow(file, "bad_ext", ext)
            else:
                # Only the allowed extensions in the config are checked for the file name and the content
                if ext in self.list_file_name_exts:
                    if self.verbose:
                        print(f'-> Processing the file for the extension: {str(ext)}')
                    res = self._search_in_file_name(file)
                    if not res:
                        if self.verbose:
                            print('-> Processing the file for the content')
                        res = self._search_in_file_content(file)

        return res

    def _search_in_file_name(self, file) -> Optional[CsvRow]:
        """
        Search the match for the file name
        :param file:
        :return:
        """
        lfile = file.stem.lower()
        for f in self.list_file_name_terms:
            if lfile.startswith(f):
                if self.verbose:
                    print(f'==> Found a file name starting with: {str(f)}')
                return CsvRow(file, None, f'file_name_start_with: "{str(f)}"')

        return None

    def _search_in_file_content(self, file) -> Optional[CsvRow]:
        """
        Search for terms in the file content
        :param file:
        :return:
        """
        try:
            with file.open(mode='r', errors='ignore') as handle:
                content = handle.read()

                perc, list_found = 0, []
                for k, v in self.list_file_text_terms:
                    found = re.search(k, content, re.IGNORECASE | re.MULTILINE)
                    if found:
                        list_found.append((k, v))
                        perc += v
                        if perc >= config.CFG_TERM_PERC_TH:
                            if self.verbose:
                                print(f'==> Found patterns in the file content: {str(list_found)}')
                            return CsvRow(file, "ptrn_in_file_content", f'\"{str(list_found)}\"')

        except PermissionError:
            print(f'EEE => Permissions error for: {str(file)}')
        except OSError as e:
            print(f'EEE => OSError: {e.strerror}')

        return None
