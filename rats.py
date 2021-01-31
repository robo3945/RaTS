# -*- coding: utf-8 -*-

import getopt
import random
import re
import string
import sys

from colorama import init, Fore, Style, deinit

from config import config
from config.config_utils import read_config_file
from misc import utils
from misc.notify import MailSender
from misc.utils import check_compile_sigs, load_ransomware_exts
from scanners.scanner_for_crypt import ScannerForCrypt
from scanners.scanner_for_file import ScannerForFile


def main(argv):
    """
    The main method
    :param argv:
    :return:
    """

    inputdir = ""
    input_file = ""
    extfilesxd = ""
    dirlistfile = ""
    outputcsv_prefix = ""
    dst_email = ""
    config_file_path = None
    ana_type = "all"  # default is to do Manifest and Crypto checks
    recursive = False
    verbose = False

    init()

    output_start = Fore.RED + config.RATS_LOGO + \
                   "\n" + Fore.BLUE + config.RATS_NAME + ' - v. ' + config.RATS_VERSION
    usage_sample = output_start + Fore.CYAN + """

Directories scan: rats.py -i <inputdir> | -l <dirlistfile> -o <outcsv> [-k|-m] [-e <notify_email>] [-r] [-h] [-c] [-v]

Single file scan: rats.py -f <file> [-k|-m] [-e <notify_email>] [-h] [-c] [-v]

-f <file>           : file to scan
-i <inputdir>       : the starting directory
-l <dirlistfile>    : a txt file with the directories to scan
-o <outcsv>         : the CSV output file prefix (without the extension)
-x <excl_ext_list>  : file extensions list to exclude from scanning (ex: "jpg,tiff") 
[-e <notify_email>] : where to send the notification
[-k]                : search for crypted files
[-m]                : search for manifest files
[-r]                : recursive search
[-c]                : path for the configuration YAML file
[-v]                : verbose mode (outcome files include all the items detected)
[-h]                : print this help
"""

    print(Style.RESET_ALL)
    try:
        opts, args = getopt.getopt(argv, "hkmrvi:x:o:e:l:c:f:")
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
        elif opt == "-f":
            input_file = arg
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

    d = {'k': 'crypto', 'm': 'manifest'}

    if (inputdir or dirlistfile) and ana_type:
        print(output_start + Fore.YELLOW + "\nHere we are!\n")

        # read the config file if it was specified
        if config_file_path is not None:
            read_config_file(config_file_path)

        # some cmd line parameters are passed to config to better manage them
        config.EXT_FILES_LIST_TO_EXCLUDE = set([x.strip() for x in extfilesxd.lower().split(sep=',')])

        dirs = []
        if dirlistfile:
            with open(dirlistfile, 'r') as handle:
                content = handle.read()
                dirs = content.split(sep='\n')
                dirs = [dir.strip() for dir in dirs if dir and dir.strip()[0] != '#']
        elif inputdir:
            dirs.append(inputdir)

        # load the signatures for file magic byte
        config.signatures = check_compile_sigs()
        # load the extension for ransomware files
        load_ransomware_exts()

        for adir in dirs:
            if ana_type == "all":
                process_dirs(adir, outputcsv_prefix + "-manifest@", 'm', dst_email, verbose=verbose,
                             recursive=recursive)
                process_dirs(adir, outputcsv_prefix + "-crypto@", 'k', dst_email, verbose=verbose,
                             recursive=recursive)
            else:
                process_dirs(adir, outputcsv_prefix + "-" + d[ana_type] + "@", ana_type, dst_email, verbose=verbose,
                             recursive=recursive)
    elif input_file and ana_type:
        print(output_start + Fore.YELLOW + "\nHere we are!\n")

        # read the config file if it was specified
        if config_file_path is not None:
            read_config_file(config_file_path)

        # load the signatures for file magic byte
        config.signatures = check_compile_sigs()
        # load the extension for ransomware files
        load_ransomware_exts()

        if ana_type == "all":
            process_file(input_file, 'm', verbose=verbose)
            process_file(input_file, 'k', verbose=verbose)
        else:
            process_file(input_file, ana_type, verbose=verbose)

    else:
        print(usage_sample)

    deinit()


def process_file(file, ana_type, verbose=False):
    """
    Process a single file
    """
    s = None
    if ana_type == 'm':
        s = ScannerForFile(verbose)
    if ana_type == 'k':
        s = ScannerForCrypt(verbose)

    s.file(file)
    s.print_found_list()


def process_dirs(inputdir, prefix_output_file, ana_type, email, verbose=False, recursive=False):
    """
    Process a dir
    """

    def rand_str(n):
        return ''.join([random.choice(string.ascii_lowercase) for i in range(n)])

    if ana_type == 'm':
        s = ScannerForFile(verbose)
    if ana_type == 'k':
        s = ScannerForCrypt(verbose)

    with utils.Timer(verbose=True) as t:
        s.search(inputdir, recursive=recursive)

    path = re.sub(r"\W+", '_', inputdir, flags=re.IGNORECASE)
    output_file = f'{prefix_output_file}{path}.t_{round(t.secs)}s.rnd_{rand_str(4)}.csv'
    msg = s.print_found_csv(output_file)

    if email:
        from_part = config.CFG_SMTP_USER
        to_part = email
        ms = MailSender()
        subject = config.RATS_NAME + ": notify"
        print(f"Send the notification e-mail to: '{to_part}'")
        ms.send_email(from_part, to_part, subject, msg)


if __name__ == "__main__":
    main(sys.argv[1:])
