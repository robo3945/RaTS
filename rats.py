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
import getopt
import random
import re
import string
import sys
from pathlib import Path

from config import config
from config.config_utils import read_config_file
from misc import utils
from misc.notify import MailSender
from scanners.scanner_for_crypt import ScannerForCrypt
from scanners.scanner_for_file import ScannerForFile


def main(argv):
    """
    The main method
    :param argv:
    :return:
    """

    inputdir = ""
    extfilesxd = ""
    dirlistfile = ""
    outputcsv_prefix = ""
    dst_email = ""
    config_file_path = None
    ana_type = "all"  # default is to do Manifest and Crypto checks
    recursive = False
    verbose = False

    output_start = config.RATS_LOGO + \
                   "\n" + config.RATS_NAME + ' - v. ' + config.RATS_VERSION
    usage_sample = output_start + """
usage: rats.py -i <inputdir> | -l <dirlistfile> -o <outcsv> [-k|-m] [-e <notify_email>] [-r] [-h]
-i <inputdir>       : the starting directory
-l <dirlistfile>    : a txt file with the directories to scan
-o <outcsv>         : the CSV output file prefix (without the extension)
-x <excl_ext_list>  : file extensions list to exclude from scanning (ex: "jpg,tiff") 
[-e <notify_email>] : where to send the notification
[-k]                : search for crypted files
[-m]                : search for manifest files
[-r]                : recursive search
[-c]                : path for the configuration YAML file
[-v]                : verbose mode
[-h]                : print this help
"""

    try:
        opts, args = getopt.getopt(argv, "hkmrvi:x:o:e:l:c:")
    except getopt.GetoptError as error:
        print('************ arguments error ************', end='\n')
        print(f'error: {str(error)}')
        print(usage_sample)
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print('************ help ************', end='\n')
            print(usage_sample)
            sys.exit()
        elif opt == '-k':
            ana_type = 'k'
        elif opt == '-m':
            ana_type = 'm'
        elif opt == '-v':
            verbose = True
        elif opt == '-r':
            recursive = True
        elif opt == "-i":
            inputdir = arg
        elif opt == "-x":
            extfilesxd = arg
        elif opt == "-l":
            dirlistfile = arg
        elif opt == "-o":
            outputcsv_prefix = arg
        elif opt == "-e":
            dst_email = arg
        elif opt == "-c":
            config_file_path = arg

    if (inputdir or dirlistfile) and ana_type:
        print(output_start + "\n\nHere we are!\n\n")

        # read the config file if it was specified
        if config_file_path is not None:
            read_config_file(config_file_path)

        # some cmd line parameters are passe to config to better manage them
        config.EXT_FILES_LIST_TO_EXCLUDE = set([x.strip() for x in extfilesxd.lower().split(sep=',')])

        dirs = []
        if dirlistfile:
            with open(dirlistfile, 'r') as handle:
                content = handle.read()
                dirs = content.split(sep='\n')
                dirs = [dir.strip() for dir in dirs if dir and dir.strip()[0] != '#']
        elif inputdir:
            dirs.append(inputdir)

        for adir in dirs:
            if ana_type == "all":
                main_process(adir, outputcsv_prefix + "-manifest@", 'm', dst_email, verbose=verbose,
                             recursive=recursive)
                main_process(adir, outputcsv_prefix + "-crypto@", 'k', dst_email, verbose=verbose,
                             recursive=recursive)
            else:
                d = {'k': 'crypto', 'm': 'manifest'}
                main_process(adir, outputcsv_prefix + "-" + d[ana_type] + "@", ana_type, dst_email, verbose=verbose,
                             recursive=recursive)
    else:
        print(usage_sample)


# Lambda expression for the random string
def rand_str(n):
    return ''.join([random.choice(string.ascii_lowercase) for i in range(n)])


def main_process(inputdir, prefix_output_file, ana_type, email, verbose=False, recursive=False):
    """
    The main main method
    :param verbose:
    :param email:
    :param recursive:
    :param ana_type:
    :param prefix_output_file:
    :param inputdir:
    """
    if ana_type == 'm':
        s = ScannerForFile(verbose)
    if ana_type == 'k':
        s = ScannerForCrypt(verbose)

    with utils.Timer(verbose=True) as t:
        s.search(inputdir, recursive=recursive)

    path = re.sub(r"\W+", '_', inputdir, flags=re.IGNORECASE)
    output_file = f'{prefix_output_file}{path}.t_{round(t.secs)}s.rnd_{rand_str(4)}.csv'
    msg = s.print_found_csv(output_file)
    if len(msg) == 0:
        print("Nothing detected!")
    elif email:
        from_part = config.RATS_NAME
        to_part = email
        ms = MailSender()
        subject = config.RATS_NAME + ": notify"
        print(f'Send the notification e-mail to: {to_part}')
        ms.send_email(from_part, to_part, subject, msg)


if __name__ == "__main__":
    main(sys.argv[1:])
