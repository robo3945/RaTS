# -*- coding: utf-8 -*-

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
        self.full_file_name = str(p).replace(';','#')
        self.file_path = str(p.parent).replace(';','#')
        self.file_name = str(p.name).replace(';','#')
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
