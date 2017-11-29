#!/usr/bin/env python
# check_sigs.py - EnergyWolf 2016
# Take a file path as argument, and check it for known file
# signatures using www.filesignatures.net

# pickling the signatures file makes subsequent look ups
# significantly faster
# https://0x00sec.org/t/get-file-signature-with-python/931

import os
from urllib.request import urlopen

import pickle as Pickle
from argparse import ArgumentParser

import binascii
from bs4 import BeautifulSoup

from config import config


def compile_sigs(path_file_signs: str, url: str):
    """ Compile the list of file signatures """

    signatures = []

    if not os.path.exists(path_file_signs):
        # TODO: modify the 19 number and adopt a better strategy
        for i in range(19):  # 19 pages of signatures on the site
            response = urlopen(url.format(i))
            html = response.read()  # get the html as a string

            soup = BeautifulSoup(html, "lxml")  # parse the source

            t_cells = soup.find_all("td", {"width": 236})  # find td elements with width=236
            for td in t_cells:
                # append (signature, description) to signatures
                sig = str(td.get_text()).replace(' ', '').lower()  # strip spaces, lowercase
                desc = str(td.find_next_sibling("td").get_text())
                signatures.append([sig, desc])

        # Add the signatures in config.py
        for sig, desc in config.KNOWN_FILE_SIGS.items():
            signatures.append([sig, desc])

        # pickle them sigs
        with open(path_file_signs, 'wb') as f:
            Pickle.dump(signatures, f)
    else:
        with open(path_file_signs, 'rb') as f:
            signatures = Pickle.load(f)

    return signatures


def check_sig_file(fn, signatures):
    """ Hex dump the file and search for signatures """

    with open(fn, 'rb') as fn:
        content = fn.read()
        return check_sig_content(content, signatures)


def check_sig_content(content, signatures):
    """ Hex dump the file and search for signatures """

    dump = str(binascii.hexlify(content))[2:-1]

    res = []
    for sig, desc in signatures:
        offset = dump.find(sig, None, config.CFG_MAX_FILE_SIGNATURE_LENGTH)
        if len(sig) > 2 and offset >= 0:
            res.append([sig, desc, offset])

    res.sort(key=lambda x: x[2])  # sort results by offset in file
    return res  # [(sig, desc, offset), (sig, desc, offset), ... etc.]


# script really starts here
if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("file_path", help="Detect signatures in file at this path")

    args = parser.parse_args()

    print("[*] Checking File for Known Signatures")
    print("[*] This may take a moment...")

    path = os.path.expanduser('./file_sigs.pickle')
    url = "http://www.filesignatures.net/index.php?page=all&currentpage={}"
    signatures = compile_sigs(path, url)
    results = check_sig_file(args.file_path, signatures)

    if results:
        # find longest signature, and desc for output formatting purposes
        big_sig = len(max([i[0] for i in results], key=lambda x: len(x)))
        big_desc = len(max([i[1] for i in results], key=lambda x: len(x)))

        print("\n[*] File Signature(s) detected:\n")
        for sig, desc, offset in results:
            s = ("[+] {0:<%ds} : {1:<%d} {2:<20s}" % (big_sig, big_desc)).format(sig, desc, "<- Offset: " + str(offset))
            print(s)

        print("\n[*] First candidate signature:\n")
        sig, desc, offset = results[0][0], results[0][1], results[0][2]
        s = ("[+] {0:<%ds} : {1:<%d} {2:<20s}" % (big_sig, big_desc)).format(sig, desc, "<- Offset: " + str(offset))
        print(s)

    else:
        print("\n[!] No File Signature Detected.\n")
