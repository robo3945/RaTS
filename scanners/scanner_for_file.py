import fnmatch
import os
import re
from operator import itemgetter
from pathlib import Path
from typing import Optional

from colorama import Fore

from config import config
from logic.csv_manager import CsvRow
from misc import utils
from scanners.scanner import Scanner

IGNORED_FILE = "Ignored file"
ERROR = "Error"


class ScannerForFile(Scanner):
    """
    The search main class
    """

    def __init__(self, csv_path=None, verbose=False, anonymize=False):
        """
        Initialization of the fields
        :return:
        """
        super().__init__(csv_path, verbose, anonymize=anonymize)
        self.ransomware_file_patterns_dict = config.RANSOMWARE_FILE_PATTERN
        self.manifest_file_name_terms_set = set(
            [line.strip().lower() for line in config.CFG_MANIFEST_FILE_NAME_TERMS.split(",") if
             line.strip() != ""])
        self.manifest_file_name_exts_set = set(
            [line.strip().lower() for line in config.CFG_MANIFEST_FILE_NAME_EXTS.split(",") if
             line.strip() != ""])
        self.file_text_terms_set = set(sorted(config.FILE_TEXT_TERMS_DIC, key=itemgetter(1), reverse=True))

    def print_config(self):
        """
        Print the values of the configuration
        :return:
        """
        print(Fore.RESET)
        print(f'{Fore.LIGHTCYAN_EX}{Scanner.sep} Config elements for "{__name__}" {Scanner.sep}')
        print()
        if self.verbose:
            print(
                f'{Fore.YELLOW}1 - ransomware file extensions detected: {Fore.GREEN}{self.ransomware_file_patterns_dict}\n')
        else:
            print(
                f'{Fore.YELLOW}1 - ransomware file extensions detected: {Fore.GREEN}{str(self.ransomware_file_patterns_dict)[:20] + "..."}\n')
        print(
            f'{Fore.YELLOW}2 - ransomware manifest file extensions analyzed:{Fore.GREEN} {str(self.manifest_file_name_exts_set)}\n')
        print(
            f'{Fore.YELLOW}  2.1 - File names detected (without the extensions):{Fore.GREEN} {str(self.manifest_file_name_terms_set)}\n')
        print(
            f'{Fore.YELLOW}  2.3 - Ransomware terms and their "relevance":{Fore.GREEN} {str(self.file_text_terms_set)}')
        print(Fore.RESET)

    def file(self, full_file_path: str):
        """
        Process a single file
        """

        self.print_config()
        print(
            f'{Fore.LIGHTCYAN_EX}{Scanner.sep} Starting search for Ransomware manifest or extension traces {str(full_file_path)} {Scanner.sep}')
        print(Fore.RESET)

        super()._internal_one_file(full_file_path)

    def search(self, path, dirs_to_exclude=None, files_to_exclude_list=None, recursive=True):
        """
        Process a Dir
        """

        self.print_config()
        print(
            f'{Fore.LIGHTCYAN_EX}{Scanner.sep} Starting search for Ransomware manifest or extension traces {str(path)} {Scanner.sep}')
        print(Fore.RESET)
        self.csv_manager.print_header()
        self._search(path, dirs_to_exclude, files_to_exclude_list, recursive)

    def _search(self, path, dirs_to_exclude=None, files_to_exclude_list=None, recursive=True):
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
                            print(f"{Fore.LIGHTBLUE_EX}+ Searching in the path:{Fore.RESET} '{entry.path}'")
                        if not Scanner.is_excluded_dir(entry.path, dirs_to_exclude) and not Scanner.is_excluded_file(
                                entry.path, files_to_exclude_list):
                            self._search(entry, dirs_to_exclude, files_to_exclude_list, recursive)
                    else:
                        self._process_a_file(entry)

                except PermissionError as e:
                    msg = f'EEE (Dir)=> Permissions error: {e}'
                    print(msg)
                    if self.verbose:
                        self.csv_manager.csv_row(entry, ERROR, msg)
                except OSError as e:
                    msg = f'EEE (Dir) => OSError {e.errno}-{e}'
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

    def _process_a_file(self, file, files_to_exclude_list=None):
        ext = Path(file).suffix.lower().replace('.', '')
        if len(ext) == 0 or ext not in config.EXT_FILES_LIST_TO_EXCLUDE:
            found = self._search_in_file(file)
            if found:
                print(f'{Fore.MAGENTA}---> Filename with problem was analysed:{Fore.RESET} {file.path}')

    def _search_in_file(self, file) -> Optional[CsvRow]:
        """
        The search for the file

        It searches for:

        1)  If the file has a Bad extension
        2)  For the allowed extensions (not the Bad exts), if it has a file name with suspect name part or terms in the content

        :param file: the file analyzed
        :return: None or the file detected
        """

        csv_row = None
        ext = Path(file).suffix.lower()
        if ext[:1] == '.':
            ext = ext[1:]

        # check if the file has a ransomware extension
        for ptrn in self.ransomware_file_patterns_dict.keys():
            if fnmatch.fnmatch(Path(file).name, ptrn):
                # if self.verbose:
                print(f'{Fore.RED}-> Ransomware file name pattern or extension found: {Fore.RESET}{ptrn}')
                csv_row = self.csv_manager.csv_row(file, "Ransomware filename pattern or extension", f"Ransomware ptrn or extension: {ptrn}")
                return csv_row

        # check if the file is a manifest file AND contains suspect terms
        if not csv_row:
            if file.stat().st_size <= config.CFG_MANIFEST_MAX_SIZE \
                    and ext in self.manifest_file_name_exts_set \
                    or f'.{ext}' in self.manifest_file_name_exts_set:

                if self.verbose:
                    print(f"{Fore.MAGENTA}-> Processing the file '{Fore.RESET}{file.path}' {Fore.MAGENTA}for the extension{Fore.RESET} '{ext}'")

                # check the filename
                csv_row = self._search_bad_terms_in_file_name(file)
                if not csv_row:
                    if self.verbose:
                        print(f"{Fore.MAGENTA}-> Processing the file '{Fore.RESET}{file.path}' {Fore.MAGENTA}for the content{Fore.RESET}")

                    # otherwise check the file content
                    csv_row = self._search_in_file_content(file)
                else:
                    if self.verbose:
                        self.csv_manager.csv_row(file, IGNORED_FILE, f"Ext not in bad exts or the file is not a manifest")

                return csv_row

    def _search_bad_terms_in_file_name(self, file) -> Optional[CsvRow]:
        """
        Search Ransomware filename terms in the file name
        :param file:
        :return:
        """
        file_lower = Path(file).stem.lower()
        for term in self.manifest_file_name_terms_set:
            if file_lower.startswith(term):
                # if self.verbose:
                print(f"{Fore.RED}--> Ransomware manifest found, filename starts with:{Fore.RESET} '{term}'")
                return self.csv_manager.csv_row(file, "Ransomware manifest filename prefix found",
                                                f"file_name_start_with: '{term}'")
            if term in file_lower:
                # if self.verbose:
                print(f"{Fore.RED}--> Ransomware manifest found, filename contains:{Fore.RESET} '{term}'")
                return self.csv_manager.csv_row(file, "Ransomware manifest filename terms found",
                                                f"file_name_contains: '{term}'")

        return None

    def _search_in_file_content(self, file) -> Optional[CsvRow]:
        """
        Search for suspect ransomware terms in the file content (if not a well known file format)
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
                is_well_known, sig, desc, offset = utils.is_known_file_type(file.name, content, verbose=self.verbose)

            if is_well_known:
                if self.verbose:
                    return self.csv_manager.csv_row(file, IGNORED_FILE,
                                                    f"Well known filetype - sig: '{sig}' - off: {str(offset)} - types: \"{desc}\"")
                return None

            else:

                with open(file.path, mode='r', errors='ignore') as handle:
                    content = handle.read()

                    sum_perc, list_found = 0, []
                    for k, v in self.file_text_terms_set:
                        found = re.search(k, content, re.IGNORECASE | re.MULTILINE)
                        if found:
                            list_found.append((k, v))
                            sum_perc += v

                    if sum_perc > 0 and len(list_found) > 0:
                        p = sum_perc / len(list_found)
                        if p >= config.CFG_TERM_PERC_TH:
                            # if self.verbose:
                            print(
                                f"{Fore.RED}--> Ransomware possible terms found in the file content: '{str(list_found)}' (mean {p}%)")
                            return self.csv_manager.csv_row(file, "Ransomware patterns in file content found",
                                                            f'\"{str(list_found)}\"')

                    if len(list_found) == 0 and self.verbose:
                        self.csv_manager.csv_row(file, IGNORED_FILE, f"No ransomware patterns found")

        except PermissionError as e:
            msg = f'EEE => Permissions error: {e}'
            print(msg)
            if self.verbose:
                self.csv_manager.csv_row(file, ERROR, msg)
        except OSError as e:
            msg = f'EEE => OSError: {e.errno}-{e}'
            print(msg)
            if self.verbose:
                self.csv_manager.csv_row(file, ERROR, msg)

        return None
