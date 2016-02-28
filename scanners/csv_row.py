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
import datetime


class CsvRow(object):
    """
    Define a bean for a CSV row
    """

    __date_format = "%Y-%m-%d %H:%M:%S"

    def __init__(self, file, type: "", desc: "", hash: ""):
        # time_t    st_atime;   /* time of last access */
        # time_t    st_mtime;   /* time of last modification */
        # time_t    st_ctime;   /* time of last status change */

        # file attributes
        self.full_file_name = str(file)
        self.file_path = file.parent
        self.file_name = file.name
        self.adate = datetime.datetime.fromtimestamp(file.stat().st_atime).strftime(CsvRow.__date_format)
        self.mdate = datetime.datetime.fromtimestamp(file.stat().st_mtime).strftime(CsvRow.__date_format)
        self.cdate = datetime.datetime.fromtimestamp(file.stat().st_ctime).strftime(CsvRow.__date_format)
        self.file_size = file.stat().st_size
        self.file_extension = file.suffix.lower()

        # other informations
        self.type = type
        self.desc = desc
        self.hash = hash

        # Conversion

    @staticmethod
    def get_header():
        return "Full file name" + ";" + \
               "file path" + ";" + \
               "file name" + ";" + \
               "file size" + ";" + \
               "Last Access Date" + ";" + \
               "Last Modification Date" + ";" + \
               "Last Status Change Date" + ";" + \
               "File extension" + ";" + \
               "File Type" + ";" + \
               "A description" + ";" + \
               "Secure Hash"

    def __repr__(self):
        return str(self.full_file_name) + ";" + \
               str(self.file_path) + ";" + \
               str(self.file_name) + ";" + \
               str(self.file_size) + ";" + \
               str(self.adate) + ";" + \
               str(self.mdate) + ";" + \
               str(self.cdate) + ";" + \
               str(self.file_extension) + ";" + \
               str(self.type) + ";" + \
               str(self.desc) + ";" + \
               str(self.hash)

    def __str__(self):
        return self.__repr__()
