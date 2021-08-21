# -*- coding: utf-8 -*-

signatures = None

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
RATS_VERSION = '1.6.3b'

# ------ Rules file -------

# files to exclude from scanning
EXT_FILES_LIST_TO_EXCLUDE = set()

# ======================> File name test

# ==> Bad file name extensions that reveal the high probability of ransomware presence

BAD_FILE_EXTS = None

# ==> File name prefixes that reveal the malware
# TODO: expand this section
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
CFG_MANIFEST_MAX_SIZE = 10_000_000  # bytes

# extension of file name to analyze to check the evidence of terms
CFG_FILE_NAME_EXTS = "html, htm, txt, bmp, jpg, gif, png"

# RegEx pattern for searching into the text: tuples with: (regex ptrn, percentage_weight)
# TODO: expand this section
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
CFG_SMTP_SSL = True
CFG_SMTP_HOST = 'smtp.gmail.com'
CFG_SMTP_PORT = 465
CFG_SMTP_USER = 'an.email@something.com'
CFG_SMTP_PWD = 'an.email.password'

# https://en.wikipedia.org/wiki/List_of_file_signatures
KNOWN_FILE_SIGS = \
    {
        "deadbeef": ["*", "DEAD BEEF"],
        "ffd8ff": ["jpg","JPEG ALL"],
        "0a0501": ["pcx", "PCX ALL"],
        "0000001c66747970": ["mpeg", "MPEG-4 Video"],
        "fffbb0": ["mp3","MP3"],
        "fffb90": ["mp3","MP3"],
        "fffb94": ["mp3","MP3"],
        "fffb54": ["mp3","MP3"],
        "fffbd4": ["mp3","MP3"]
    }

URL_FOR_SIGNATURES = "http://www.filesignatures.net/index.php?page=all&currentpage={}"
CFG_PATH_FOR_SIGNATURES = './file_sigs.json'
# the maximum lenght of the signature to find in the Dump file
CFG_MAX_FILE_SIGNATURE_LENGTH = 60
# the minimum bytes length for checking the compressed item
CFG_COMPRESSED_CONTENT_MIN_LEN = 100
CFG_ENTROPY_CONTENT_MIN_LEN = 100
