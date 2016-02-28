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

from pathlib import Path
from operator import itemgetter
from config import config
import re

from scanners.csv_row import CsvRow
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
        self.list_file_bad_exts = [line.strip().lower() for line in config.file_bad_exts.split(",") if
                                   line.strip() != ""]
        self.list_file_name_terms = [line.strip().lower() for line in config.file_name_terms.split(",") if
                                     line.strip() != ""]
        self.list_file_name_exts = [line.strip().lower() for line in config.file_name_exts.split(",") if
                                    line.strip() != ""]
        self.list_file_text_terms = sorted(config.file_text_terms_dic, key=itemgetter(1), reverse=True)

    def print_config(self):
        """
        Print the values of the configuration
        :return:
        """
        print("%s Config elements for '%s' %s" % (Scanner.sep, __name__, Scanner.sep))
        print()
        print("Bad file extensions detected: " + str(self.list_file_bad_exts))
        print("File extensions analyzed: " + str(self.list_file_name_exts))
        print("File names detected (without the extensions): " + str(self.list_file_name_terms))
        print("List with terms and their \"relevance\": " + str(self.list_file_text_terms))
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
        print(Scanner.sep + " Starting search Ransomware manifest traces in: " + str(path) + " " + Scanner.sep)
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
                    print("- Processing the file: " + str(f))
                found = self.__search_in_file(f)
                if found:
                    print("=====> Found matches in: " + str(f))
                    self.found.append(found)

            # passo ricorsivo nelle directory
            if recursive:
                dir_list = [x for x in p.iterdir() if not x.is_symlink() and x.is_dir()]
                for x in dir_list:
                    if self.verbose:
                        print("+ Searching in the path: " + str(x))
                    self._search(x, recursive)
        except PermissionError:
            print("EEE => Permissions error for: " + str(p))
        except OSError as e:
            print("EEE => OSError: " + e.strerror)

    def __search_in_file(self, file) -> str:
        """
        The search for the file

        It searches for:

        1)  If the file has a Bad extension. If yes it detect it and continue on the next file
        2)  If, for the extensions allowed (not the Bad exts), it has a file name with suspect name part or terms
            in the content. If yes it detect it and continue on the next file

        :param file: the file analyzed
        :return: None or the file detected
        """

        res = None

        # check only the files with max a size
        if file.stat().st_size <= config.max_size:

            # check if the file has a bad extension
            ext = file.suffix.lower()
            if ext in self.list_file_bad_exts:
                if self.verbose:
                    print("-> Found bad extension in the file: " + str(ext))
                res = CsvRow(file, "bad_ext", ext, 0)
            else:
                # Only the allowed extensions in the config are checked for the file name and the content
                if ext in self.list_file_name_exts:
                    if self.verbose:
                        print("-> Processing the file for the extension: " + str(ext))
                    res = self._search_in_file_name(file)
                    if not res:
                        if self.verbose:
                            print("-> Processing the file for the content")
                        res = self._search_in_file_content(file)



        return res

    def _search_in_file_name(self, file) -> str:
        """
        Search the match for the file name
        :param file:
        :return:
        """
        for f in self.list_file_name_terms:
            if file.stem.lower().startswith(f):
                if self.verbose:
                    print("==> Found a file name starting with: " + str(f))
                return CsvRow(file, "file_name_start_with", '"' + str(f) + '"', 0)

        return None

    def _search_in_file_content(self, file) -> str:
        """
        Search for terms in the file content
        :param file:
        :return:
        """
        try:
            with file.open(mode='r', errors='ignore') as handle:
                content = handle.read()

                perc = 0
                for k, v in self.list_file_text_terms:
                    found = re.search(k, content, re.IGNORECASE | re.MULTILINE)
                    if found:
                        perc += v
                        if perc >= config.threshold_terms_perc:
                            if self.verbose:
                                print("==> Found a pattern in the file content: " + str(k))
                            return CsvRow(file, "ptrn_in_file_content", '"' + str(k) + '"', 0)

        except PermissionError:
            print("EEE => Permissions error for: " + str(file))
        except OSError as e:
            print("EEE => OSError: " + e.strerror)

        return None
