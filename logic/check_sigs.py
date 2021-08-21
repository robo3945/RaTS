# check_sigs.py - EnergyWolf 2016
# Take a file path as argument, and check it for known file
# signatures using www.filesignatures.net

# pickling the signatures file makes subsequent look ups
# significantly faster
# https://0x00sec.org/t/get-file-signature-with-python/931
import json
import os
from pprint import pprint
from urllib.request import urlopen

from argparse import ArgumentParser

import binascii
from bs4 import BeautifulSoup

from config import config


def compile_sigs(path_file_signs: str, url: str):
    """ Compile the list of file signatures """

    signatures = dict()
    if not os.path.exists(path_file_signs):

        print("--- Signature Pack building ---")

        # look at every page: maximum 100
        last_html = None
        for i in range(1,100):
            response = urlopen(url.format(i))
            html = response.read()  # get the html as a string

            # if the last page is equal to the current stop
            if html == last_html:
                break
            last_html = html
            soup = BeautifulSoup(html, "lxml")  # parse the source

            t_cells = soup.find_all("td", {"width": 147})  # find td elements with width=236
            for td in t_cells:
                # append (signature, description) to signatures
                ext = str(td.get_text()).replace(' ', '').lower()
                sign = str(td.find_next_sibling("td").get_text()).replace(' ', '').lower()  # strip spaces, lowercase
                descr = str(td.find_next_sibling("td").find_next_sibling("td").get_text())

                if sign not in signatures.keys():
                    signatures[sign] = [(ext, descr)]
                else:
                    signatures[sign].append((ext, descr))

        # Add the signatures in config.py
        for sign, value in config.KNOWN_FILE_SIGS.items():
            signatures[sign] = value

        # pickle them sigs
        with open(path_file_signs, 'wt') as f:
            js = json.dumps({'sig_list': signatures}, indent=2)
            f.write(js)

        print(js)
        print(f"Signatures list size: {len(signatures)}")
        print("--- // Signature Pack building ---")

    else:
        with open(path_file_signs, 'rt') as f:
            signatures = json.loads(f.read())['sig_list']

    return signatures


def check_sig_file(fn, signatures):
    """ Hex dump the file and search for signatures """

    with open(fn, 'rb') as fn:
        content = fn.read()
        return check_sig_content(content, signatures)


def check_sig_content(content: bytes, signatures):
    """ Hex dump the file and search for signatures """

    dump = binascii.hexlify(content[:config.CFG_MAX_FILE_SIGNATURE_LENGTH]).decode()

    res = []
    for s, d in signatures.items():
        off = dump.find(s)
        if len(s) > 2 and off >= 0:
            res.append([s, d, off])

    res.sort(key=lambda x: x[2])  # sort results by offset in file
    return res  # [(sig, desc, offset), (sig, desc, offset), ... etc.]


# script really starts here
if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("file_path", help="Detect signatures in file at this path")

    args = parser.parse_args()

    print("[*] Checking File for Known Signatures")
    print("[*] This may take a moment...")

    path = os.path.expanduser('./file_sigs.json')
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
