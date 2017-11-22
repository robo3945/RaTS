# -*- coding: utf-8 -*-

"""
RaTS: Ransomware Traces Scanner
Copyright (C) 2015, 2016, 2017 Roberto Battistoni (r.battistoni@gmail.com)

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

RATS_NAME = 'RaTS'
RATS_LOGO = \
"""
______    _____ _____ 
| ___ \  |_   _/  ___|
| |_/ /__ _| | \ `--. 
|    // _` | |  `--. \\
| |\ \ (_| | | /\__/ /
\_| \_\__,_\_/ \____/ 
"""
RATS_VERSION = '0.9a'

# ------ Rules file -------

# ======================> File name test

# ==> 1-step: Bad file name extensions that reveal the high probability of ransomware presence
FILE_BAS_EXTS = """
.aaa,
.cryptotorlocker,
.ecc,
.encrypted,
.exx,
.ezz,
.frtrss,
.locky,
.vault,
.vvv
"""

# ==> 2-step: File name prefixs that reveal the malware
MANIFEST_FILE_NAME_TERM = """
cryptolocker,
!Decrypt-All-Files-,
decrypt_instruct,
enc_files,
help_decrypt,
help_restore,
help_recover_instructions,
help_your_file,
HOW_DECRYPT,
how to decrypt,
how_recover,
how_to_decrypt,
how_to_recover,
howto_restore_file,
howtodecrypt,
install_tor,
last_chance,
message,
readme_for_decrypt,
recovery_file,
recovery_key,
restore_files_
vault,
"""

# ==> 3-step: check the terms inside the content of the 2-step files

# The maximum size of the file to be analyzed: ransomware disclaimer are little
MANIFEST_MAX_SIZE = 40000  # bytes

# extension of file name to analyze to check the evidence of terms ("file_text_terms_dic")
# with certain percentage (>100)
FILE_NAME_EXTS = ".html, .txt"

# RegEx pattern to search into the text: there is a tuple with regex ptrn and a percentage that is its weight
FILE_TEXT_TERMS_DIC = [(r'\bcryptowall\b', 100),
                       (r'\bcryptolocker\b', 100),
                       (r'\bCryptoDefense\b', 100),
                       (r'\bprivate\s+key\b', 80),
                       (r'\bAES-256\b', 80),
                       (r'\bRSA-2048\b', 80),
                       (r'.onion', 50),
                       (r'\bbitcoin\b', 50),
                       (r'\btor\b', 30),
                       (r'\bencrypted\b', 30),
                       (r'\bencryption\b', 30),
                       (r'\bcrypto\b', 30)]

# ==> threshold for the detection of the terms in the text files
TERM_PREC_TH = 100

# ----------------------------------------------------------

# threshold for the randomness test
COMPR_RAND_TH = 0.70
ENTR_RAND_TH = 7.80
# rand_first_n_bytes_to_check = 100_000_000
NUM_BYTES_TO_RAND_CHECK = None

# ----------------------------------------------------------

# notification settings
SMTP_HOST = 'smtp.gmail.com'
SMTP_PORT = 465
SMTP_USER = 'an.email@something.com'
SMTP_PWD = 'an.email.password'

# ----------------------------------------------------------
# file type signatures

"""
        b'\x50\x4B\x03\x04': "zip,jar,odt,ods,odp,docx,xlsx,pptx,vsdx,apk,aar" ,
        b'\x50\x4B\x05\x06': "zip,jar,odt,ods,odp,docx,xlsx,pptx,vsdx,apk,aar",
        b'\x50\x4B\x07\x08': "zip,jar,odt,ods,odp,docx,xlsx,pptx,vsdx,apk,aar",
        b'\x1F\x8B\x08': "GZ",
        b'\x52\x61\x72\x21\x1A\x07\x00': "RAR1.5",
        b'\x52\x61\x72\x21\x1A\x07\x10\x00': "RAR5.0",
        b'\x43\x57\x53': "SWF:flash file",
        b'\x46\x57\x53': "SWF:flash player",
        b'\x49\x53\x63\x28': "CAB: Install Shield compressed file",
        b'\x4D\x53\x43\x46': "CAB: Microsoft cabinet file",
        b'\x37\x7A\xBC\xAF\x27\x1C': "7Z: 7-Zip compressed file",
        b'\x25\x50\x44\x46': "PDF",
        b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C': "asf, wma, wmv"

"""

# https://en.wikipedia.org/wiki/List_of_file_signatures
KNOWN_FILE_SIGS = \
    {
        "deadbeef": "DEAD BEEF",
        "ffd8ff": "JPEG ALL",
        "0a0501": "PCX ALL"
    }

PATH_FOR_SIGNATURES = './file_sigs.pickle'
URL_FOR_SIGNATURES = "http://www.filesignatures.net/index.php?page=all&currentpage={}"
# the maximum lenght of the signature to find in the Dump file
MAX_SIGNATURE_LENGHT = 60
# the minimun length to consider the compression value
MIN_LEN_COMPRESSED_CONTENT = 100