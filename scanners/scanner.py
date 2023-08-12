
import abc
from genericpath import samefile
import os
from pathlib import Path
from typing import List

from colorama import Fore

from logic.csv_manager import CsvRow, CsvManager


class Scanner(metaclass=abc.ABCMeta):
    """
    The search abstract main class
    """

    sep = '---***---'

    def __init__(self, csv_path=None, verbose=False, anonymize=False):
        """
        Initialization of the fields
        :return:
        """
        self.csv_path = csv_path
        self.verbose = verbose

        self.csv_manager = CsvManager(None)

        # opens the csv file's handle
        if self.csv_path:
            self.csv_handle = open(self.csv_path, "w", errors='ignore')
            self.csv_manager = CsvManager(self.csv_handle, anonymize=anonymize)

    @abc.abstractmethod
    def print_config(self):
        """
        Print the values of the configuration
        :return:
        """
        raise NotImplementedError

    @abc.abstractmethod
    def file(self, path: str):
        """
        The main search method: process a file

        :param path:
        :return:
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _process_a_file(self, file: os.DirEntry):
        raise NotImplementedError

    @abc.abstractmethod
    def search(self, path, dirs_to_exclude=None, files_to_exclude_list=None, recursive=True):
        """
        The main search method: process a directory
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _search(self, path, dirs_to_exclude=None, files_to_exclude_list=None, recursive=True):
        """
        The main recursive Search method
        """
        raise NotImplementedError

    def _internal_one_file(self, full_file_path) -> CsvRow:
        """
        Process a single file

        :param full_file_path:
        :return:
        """
        dir = Path(full_file_path)
        if dir.is_file():
            with os.scandir(dir.parent) as it:
                for f in it:
                    try:
                        if f.is_file() and f.name == dir.name:
                            return self._process_a_file(f)
                    except PermissionError as e:
                        print(f'EEE => Permissions error: {e}')
                    except OSError as e:
                        print(f'EEE => OSError {e.errno}-{e}')

        print(f"{Fore.MAGENTA}-> No file processed '{Fore.RESET}{full_file_path}'")

    @staticmethod
    def is_excluded_dir(path: str, dirs_to_exclude: List[str]):
        """
        Determines if the path is in the excluded dirs list

        :param path:
        :param dirs_to_exclude:
        :return:
        """

        if dirs_to_exclude and len(dirs_to_exclude) > 0:
            for it in dirs_to_exclude:
                try:
                    if (samefile(os.path.abspath(path), it)):
                        print(f"{Fore.MAGENTA}-> Dir excluded: '{Fore.RESET}{path}'")
                        return True
                except (OSError, ValueError):
                    pass

        return False

    @staticmethod
    def is_excluded_file(path: str, files_to_exclude_list: List[str]):
        """
        Determines if the path is in the excluded dirs list

        :param path:
        :param files_to_exclude_list:
        :return:
        """

        if files_to_exclude_list and len(files_to_exclude_list) > 0:
            for it in files_to_exclude_list:
                try:
                    if os.path.samefile(path, it):
                        print(f"{Fore.MAGENTA}-> File excluded: '{Fore.RESET}{path}'")
                        return True
                except (OSError, ValueError):
                    pass

        return False

    def read_csv_content(self) -> str:
        if self.csv_path:
            with open(self.csv_path, "r", encoding="utf8", errors='ignore') as handle:
                return handle.read()

    def close_csv_handle(self):
        self.csv_handle.close()
