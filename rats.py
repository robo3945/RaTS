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
from scanners.scanner import Scanner
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
    filesxd = ""
    dirlistfile = ""
    outputcsv_prefix = ""
    dst_email = ""
    config_file_path = None
    ana_type = "all"  # default is to do Manifest and Crypto checks
    recursive = False
    verbose = False
    crypto_type='all'

    init()

    output_start = Fore.RED + config.RATS_LOGO + \
                   "\n" + Fore.BLUE + config.RATS_NAME + ' - v. ' + config.RATS_VERSION
    usage_sample = Fore.CYAN + """

Directories scan: rats.py -i <inputdir> | -l <dirlistfile> -o <outcsv> [-k|-m] [-e <notify_email>] [-r] [-h] [-c] [-v]

Single file scan: rats.py -f <file> [-k|-m] [-e <notify_email>] [-h] [-c] [-v]

-f <file>           : file to scan
-i <inputdir>       : the starting directory
[-l <dirlistfile>]  : txt file with the directories to include in the scan
[-z <dirlistfile>]  : txt file with the directories to exclude from the scan
-o <outcsv>         : the CSV output file prefix (without the extension)
[-x <excl_ext_list>]: file extensions list to exclude from scanning (ex: "jpg,tiff") 
[-e <notify_email>] : where to send the notification
[-k]                : search for crypted files
[-t]                : crypto engine (all, entropy, compression)
[-m]                : search for manifest files
[-r]                : recursive search
[-c]                : path for the configuration YAML file
[-v]                : verbose mode (outcome files include all the items detected)
[-h]                : print this help
"""

    print(Style.RESET_ALL)
    print(output_start + Fore.YELLOW + "\nHere we are!\n")

    try:
        opts, args = getopt.getopt(argv, "hkmrvi:x:o:e:l:c:f:t:z:")
    except getopt.GetoptError as error:
        print('************ arguments error ************', end='\n')
        print(f'error: {str(error)}')
        print(usage_sample)
        sys.exit(2)

    print(Fore.LIGHTCYAN_EX + "---***--- Cmd line args ---***---" + Fore.RESET)

    for opt, arg in opts:
        if opt == '-h':
            print('************ help ************', end='\n')
            print(usage_sample)
            sys.exit()
        elif opt == '-k':
            ana_type = 'k'
            print(Fore.LIGHTCYAN_EX + "-k" + Fore.RESET)
        elif opt == '-t':
            crypto_type = arg
            print(Fore.LIGHTCYAN_EX + f"-t {arg}" + Fore.RESET)
        elif opt == '-m':
            ana_type = 'm'
            print(Fore.LIGHTCYAN_EX + "-m" + Fore.RESET)
        elif opt == '-v':
            verbose = True
            print(Fore.LIGHTCYAN_EX + "-v" + Fore.RESET)
        elif opt == '-r':
            recursive = True
            print(Fore.LIGHTCYAN_EX + "-r" + Fore.RESET)
        elif opt == "-i":
            inputdir = arg
            print(Fore.LIGHTCYAN_EX + f"-i {arg}" + Fore.RESET)
        elif opt == "-f":
            input_file = arg
            print(Fore.LIGHTCYAN_EX + f"-f {arg}" + Fore.RESET)
        elif opt == "-x":
            extfilesxd = arg
            print(Fore.LIGHTCYAN_EX + f"-x {arg}" + Fore.RESET)
        elif opt == "-z":
            filesxd = arg
            print(Fore.LIGHTCYAN_EX + f"-z {arg}" + Fore.RESET)
        elif opt == "-l":
            dirlistfile = arg
            print(Fore.LIGHTCYAN_EX + f"-l {arg}" + Fore.RESET)
        elif opt == "-o":
            outputcsv_prefix = arg
            print(Fore.LIGHTCYAN_EX + f"-o {arg}" + Fore.RESET)
        elif opt == "-e":
            dst_email = arg
            print(Fore.LIGHTCYAN_EX + f"-e {arg}" + Fore.RESET)
        elif opt == "-c":
            config_file_path = arg
            print(Fore.LIGHTCYAN_EX + f"-c {arg}" + Fore.RESET)

    d = {'k': 'crypto', 'm': 'manifest'}

    if (inputdir or dirlistfile) and ana_type:

        # read the config file if it was specified
        if config_file_path is not None:
            read_config_file(config_file_path)

        # some cmd line parameters are passed to config to better manage them
        config.EXT_FILES_LIST_TO_EXCLUDE = set([x.strip() for x in extfilesxd.lower().split(sep=',')])

        # organize the directories to process: main dir or list of dirs
        dirs_to_process = list()
        if dirlistfile:
            dirs_to_process = process_dir_file(dirlistfile)
        elif inputdir:
            dirs_to_process.append(inputdir)

        # read the list of dirs to exclude
        dirs_to_exclude = list()
        if filesxd:
            dirs_to_exclude = process_dir_file(filesxd)

        # load the signatures for file magic byte
        config.signatures = check_compile_sigs()
        # load the extension for ransomware files
        load_ransomware_exts()

        for adir in dirs_to_process:
            try:
                if ana_type == "all":
                    process_dirs(adir,
                                 dirs_to_exclude,
                                 outputcsv_prefix + "-manifest@", 'm',
                                 crypto_type=crypto_type,
                                 email=dst_email,
                                 verbose=verbose,
                                 recursive=recursive)
                    process_dirs(adir,
                                 dirs_to_exclude,
                                 outputcsv_prefix + "-crypto@", 'k',
                                 crypto_type=crypto_type,
                                 email=dst_email,
                                 verbose=verbose,
                                 recursive=recursive)
                else:
                    process_dirs(adir,
                                 dirs_to_exclude,
                                 outputcsv_prefix + "-" + d[ana_type] + "@", ana_type,
                                 crypto_type=crypto_type,
                                 email=dst_email,
                                 verbose=verbose,
                                 recursive=recursive)
            except FileNotFoundError as e:
                msg = f'EEE (MainScanDir) => FileNotFound error: {e}'
                print(msg)

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


def process_dir_file(dirlistfile):
    """
    Processes a file that contains a list of directories

    :param dirlistfile:
    :return:
    """
    with open(dirlistfile, 'r') as handle:
        content = handle.read()
        dirs_to_process = content.split(sep='\n')
        dirs_to_process = [dir.strip() for dir in dirs_to_process if dir and dir.strip()[0] != '#']
    return dirs_to_process


def process_file(file, ana_type, crypto_type, verbose=False):
    """
    Process a file
    """
    s = None
    if ana_type == 'm':
        s = ScannerForFile(verbose = verbose)
    if ana_type == 'k':
        s = ScannerForCrypt(rand_test=crypto_type, verbose = verbose)

    print()
    print(f'{Fore.LIGHTCYAN_EX}{Scanner.sep} Found items {Scanner.sep}{Fore.RESET}')
    print(s.file(file))


def process_dirs(inputdir, dirs_to_exclude, prefix_output_file, ana_type, crypto_type, email, verbose=False, recursive=False):
    """
    Process a dir
    """

    def rand_str(n):
        return ''.join([random.choice(string.ascii_lowercase) for _ in range(n)])

    path = re.sub(r"\W+", '_', inputdir[0:64], flags=re.IGNORECASE)
    # filename = f'{path}.t_{round(t.secs)}s.rnd_{rand_str(4)}.csv'
    filename = f'{path}.rnd_{rand_str(4)}.csv'
    output_file = f'{prefix_output_file}{filename}'

    print(f'{Fore.LIGHTCYAN_EX}Open CSV file for write outcome: {output_file}{Fore.RESET}')

    scanner = None
    if ana_type == 'm':
        scanner = ScannerForFile(output_file, verbose)
    if ana_type == 'k':
        scanner = ScannerForCrypt(csv_path=output_file, rand_test=crypto_type, verbose = verbose)

    if scanner:
        with utils.Timer(verbose=True):
            scanner.search(inputdir, dirs_to_exclude, recursive=recursive)
            scanner.close_csv_handle()
            print(f'{Fore.LIGHTCYAN_EX}Closed CSV file for write outcome: {output_file}{Fore.RESET}')

    # msg = scanner.print_found_csv(output_file)

    if email:
        from_part = config.CFG_SMTP_USER
        to_part = email
        ms = MailSender()
        subject = config.RATS_NAME + f": notify for {'manifest' if ana_type == 'm' else 'crypto'} processing: {filename}"
        print(f"{subject}, sent to: '{to_part}'")
        ms.send_email(from_part, to_part, subject, scanner.read_csv_content(), filename)


if __name__ == "__main__":
    #import ntpath
    #ntpath.realpath = ntpath.abspath
    main(sys.argv[1:])
