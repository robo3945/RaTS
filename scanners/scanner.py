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
import abc

from scanners.csv_row import CsvRow


class Scanner(metaclass=abc.ABCMeta):
    """
    The search abstract main class
    """

    sep = '---***---'

    def __init__(self, verbose=False):
        """
        Initialization of the fields
        :return:
        """
        self.found = []
        self.verbose = verbose

    @abc.abstractmethod
    def print_config(self):
        """
        Print the values of the configuration
        :return:
        """
        raise NotImplementedError

    @abc.abstractmethod
    def search(self, path, recursive=True):
        """
        The main search method

        :param path:
        :param recursive:
        :return:
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _search(self, path, recursive=True):
        """
        The main recursive Search method
        :param path:
        :param recursive:
        :return:
        """
        raise NotImplementedError

    def print_found_list(self):
        """
        Print the list of found items
        :return:
        """
        print(Scanner.sep + " Found items " + Scanner.sep)
        print(self.found)

    def print_found_csv(self, file_name=None):
        """
        Print the list of found items in the form of CSV file
        :param file_name:
        :return:
        """

        s = ''
        if self.found:
            s = CsvRow.get_header() + "\n"
            for x in self.found:
                s = s + str(x) + "\n"

            print("******************** CSV ****************************")
            print(s, end="")
            print("*****************************************************")

            if file_name and s.split():
                with open(file_name, "w") as handle:
                    handle.write(s)

        return s
