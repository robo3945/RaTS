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
import getopt
import re
import sys
from pathlib import Path

from config import config
from misc.notify import MailSender
from scanners.scanner_for_crypt import ScannerForCrypt
from scanners.scanner_for_file import ScannerForFile


def main(argv):
    """
    The main method
    :param argv:
    :return:
    """

    inputdir = ''
    dirlistfile = ''
    outputcsv_prefix = ''
    dst_email = ''
    ana_type = "all"  # default is to do Manifest and Crypto checks
    recursive = False
    verbose = False

    usage_sample = \
        config.name + ' - v. ' + config.version + """
usage: rats.py -i <inputdir> | -l <dirlistfile> -o <outcsv> [-k|-m] [-e <notify_email>] [-r] [-h]
-i <inputdir>       : the starting directory
-l <dirlistfile>  : a txt file with the directories to scan
-o <outcsv>         : the CSV output file prefix (without the extension)
[-e <notify_email>] : where to send the notification
[-k]                : search for crypted files
[-m]                : search for manifest files
[-r]                : recursive search
[-v]                : verbose mode
[-h]                : print this help
"""

    try:
        opts, args = getopt.getopt(argv, "hkmrvi:o:e:l:")
    except getopt.GetoptError as error:
        print('************ arguments error ************', end='\n\n\n')
        print('error: ' + str(error))
        print(usage_sample)
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print('************ help ************', end='\n\n\n')
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
        elif opt == "-l":
            dirlistfile = arg
        elif opt == "-o":
            outputcsv_prefix = arg
        elif opt == "-e":
            dst_email = arg

    if (inputdir or dirlistfile) and ana_type:
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
                main_process(adir, outputcsv_prefix + "-manifest@", 'm', dst_email, verbose=verbose, recursive=recursive)
                main_process(adir, outputcsv_prefix + "-crypto@", 'k', dst_email, verbose=verbose, recursive=recursive)
            else:
                main_process(adir, outputcsv_prefix + "-" + ana_type + "@", ana_type, dst_email, verbose=verbose,
                             recursive=recursive)
    else:
        print('************ no arguments given ************', end='\n\n\n')
        print(usage_sample)


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

    # Check the inputdir

    p = Path(inputdir)
    try:
        [x for x in p.iterdir() if not x.is_symlink() and x.is_file()]
    except PermissionError:
        print("EEE => Permissions error for: " + str(inputdir))
        sys.exit(1)
    except OSError as e:
        print("EEE => OSError: " + e.strerror)
        sys.exit(1)

    if ana_type == 'm':
        s = ScannerForFile(verbose)
    if ana_type == 'k':
        s = ScannerForCrypt(verbose)

    s.search(inputdir, recursive=recursive)
    suffix = re.sub(r"\W+", '_', inputdir, flags=re.IGNORECASE)
    output_file = prefix_output_file + suffix + '.csv'
    msg = s.print_found_csv(output_file)
    if not msg.split():
        print("Nothing detected!")
    elif email:
        from_part = config.name
        to_part = email
        ms = MailSender()
        subject = config.name + ": notify"
        print("Send the notification e-mail to: " + to_part)
        ms.send_email(from_part, to_part, subject, msg)


if __name__ == "__main__":
    main(sys.argv[1:])
