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
RATS_VERSION = '1.0b'

# ------ Rules file -------

# ======================> File name test

# ==> Bad file name extensions that reveal the high probability of ransomware presence
# check this project: https://gist.github.com/CHEF-KOCH/6ccf6143b567685dab9ccd2286ee4db0
FILE_BAS_EXTS = """.ecc, .ezz, .exx, .zzz, .xyz, .aaa, *.cryp1, .abc, .ccc, .vvv, *.zepto, .xxx, .ttt, .micro, 
.encrypted, .locked, .crypto, _crypt, .crinf, .r5a, .XRNT, .XTBL, .crypt, .R16M01D05, .pzdc, .good, .LOL!, .OMG!, 
.RDM, .RRK, .encryptedRSA, .crjoker, .EnCiPhErEd, .LeChiffre, .keybtc@inbox_com, .0x0, .bleep, .1999, .vault, .HA3, 
.toxcrypt, .magic, .SUPERCRYPT, .CTBL, .CTB2, .diablo6, .Lukitus, .locky """


# ==> File name prefixes that reveal the malware
MANIFEST_FILE_NAME_TERMS = """
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

# ==> terms inside the content of the found manifest files

# The maximum size of the file to be analyzed: ransomware disclaimer are little
CFG_MANIFEST_MAX_SIZE = 40_000  # bytes

# extension of file name to analyze to check the evidence of terms
CFG_FILE_NAME_EXTS = ".html, .txt"

# RegEx pattern for searching into the text: tuples with: (regex ptrn, percentage_weight)
FILE_TEXT_TERMS_DIC = [(r'\bcryptowall\b', 99),
                       (r'\bcryptolocker\b', 99),
                       (r'\bCryptoDefense\b', 99),
                       (r'\bloker\b', 99),
                       (r'\bprivate\s+key\b', 80),
                       (r'\bAES-256\b', 80),
                       (r'\bRSA-2048\b', 80),
                       (r'.onion', 50),
                       (r'torproject.org', 50),
                       (r'\bbitcoin\b', 50),
                       (r'\btor\b', 30),
                       (r'\bencrypted\b', 30),
                       (r'\bencryption\b', 30),
                       (r'\bcrypto\b', 30)]

# threshold for the detection of the terms in the text files
CFG_TERM_PERC_TH = 100

# ----------------------------------------------------------

# threshold for the randomness test
CFG_COMPR_RAND_TH = 0.70
CFG_ENTR_RAND_TH = 7.80
# rand_first_n_bytes_to_check = 100_000_000
CFG_N_BYTES_2_RAND_CHECK = None

# ----------------------------------------------------------

# notification settings
CFG_SMTP_HOST = 'smtp.gmail.com'
CFG_SMTP_PORT = 465
CFG_SMTP_USER = 'an.email@something.com'
CFG_SMTP_PWD = 'an.email.password'

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

URL_FOR_SIGNATURES = "http://www.filesignatures.net/index.php?page=all&currentpage={}"
CFG_PATH_FOR_SIGNATURES = './file_sigs.pickle'
# the maximum lenght of the signature to find in the Dump file
CFG_MAX_FILE_SIGNATURE_LENGTH = 60
# the minimum bytes length for checking the compressed item
CFG_COMPRESSED_CONTENT_MIN_LEN = 100
