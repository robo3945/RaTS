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
import datetime
from pathlib import Path

import bitmath


class CsvRow(object):
    """
    Define a bean for a CSV row
    """

    _date_format = "%Y-%m-%d %H:%M:%S"

    def __init__(self, file, type="", desc=""):
        # time_t    st_atime;   /* time of last access */
        # time_t    st_mtime;   /* time of last modification */
        # time_t    st_ctime;   /* time of last status change */

        # file attributes

        p = Path(file)
        self.full_file_name = str(p)
        self.file_path = p.parent
        self.file_name = p.name
        self.adate = datetime.datetime.fromtimestamp(file.stat().st_atime).strftime(CsvRow._date_format)
        self.mdate = datetime.datetime.fromtimestamp(file.stat().st_mtime).strftime(CsvRow._date_format)
        self.cdate = datetime.datetime.fromtimestamp(file.stat().st_ctime).strftime(CsvRow._date_format)
        self.file_size = file.stat().st_size
        self.file_extension = p.suffix.lower()

        # other informations
        self.type = type
        self.desc = desc

        # Conversion

    @staticmethod
    def get_header():
        return "Full file name;" + \
               "file path;" + \
               "file name;" + \
               "file size;" + \
               "File extension;" + \
               "File Type;" + \
               "A description;" + \
               "Last Access Date and Time;" + \
               "Last Modification Date and Time;" + \
               "Last Status Change Date and Time"

    def __repr__(self):
        file_size = bitmath.Byte(bytes=self.file_size).best_prefix()
        str_file_size = file_size.format("{value:.2f} {unit}")
        return f'{self.full_file_name};{self.file_path};{self.file_name};{str_file_size};{self.file_extension};{self.type};{self.desc};{self.adate};{str(self.mdate)};{str(self.cdate)}'

    def __str__(self):
        return self.__repr__()

    def min_print(self):
        """
        string for console logging purpose
        :return:
        """

        return f'{self.file_path}|{self.file_name}|{self.type}|{self.desc}'
