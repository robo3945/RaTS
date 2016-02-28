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

name = 'RaTS'
version = '0.1b'

# ------ Rules file -------

# ======================> File name test

# ==> 1-step: Bad file name extensions that reveal the high probability of ransomware presence
file_bad_exts = """
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
file_name_terms = """
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
max_size = 40000  # bytes

# extension of file name to analyze to check the evidence of terms ("file_text_terms_dic")
# with certain percentage (>100)
file_name_exts = ".html, .txt"

# RegEx pattern to search into the text: there is a tuple with regex ptrn and a percentage that is its weight
file_text_terms_dic = [(r'\bcryptowall\b', 100),
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

# ==> threshold for the detection of the terms in the textual files
threshold_terms_perc = 100

# ======================> Crypto test

# threshold for the randomness test
randomness_threshold = 1.0
rand_first_n_bytes_to_check = 100000000  # 1 MB

# ----------------------------------------------------------

# notification settings
smtp_host = 'smtp.gmail.com'
smtp_port = 465
smtp_user = 'an.email@something.com'
smtp_passwd = 'an.email.password'

# file type signatures

compressed_signatures = \
    [("ZIP: PKZIP archive_1", b'\x50\x4B\x03\x04'),
     ("GZ", b'\x1F\x8B\x08'),
     ("RAR", b'\x52\x61\x72\x21\x1A\x07\x00'),
     ("SWF:flash file", b'\x43\x57\x53'),
     ("SWF:flash player", b'\x46\x57\x53'),
     ("CAB: Install Shield compressed file", b'\x49\x53\x63\x28'),
     ("CAB: Microsoft cabinet file", b'\x4D\x53\x43\x46'),
     ("7Z: 7-Zip compressed file", b'\x37\x7A\xBC\xAF\x27\x1C')
     ]
