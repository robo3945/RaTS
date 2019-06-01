import sys
from pprint import pprint

import yaml

from config import config


def read_config_file(path: str):
    """
    Read the YAML config file and overwrite the configuration variables
    :param path:
    :return:
    """

    print("---***--- Read configuration file {0} ---***---".format(path))
    try:
        with open(path, 'r') as cfg_file:
            #cfg_dict = yaml.load(cfg_file) ==> deprecated with new version of the lib
            cfg_dict = yaml.load(cfg_file, Loader=yaml.BaseLoader)

            # print(cfg_dict)
        if cfg_dict is not None:
            # manifest_sec
            config.CFG_MANIFEST_MAX_SIZE = int(cfg_dict['manifest_sec']['CFG_MANIFEST_MAX_SIZE'])
            config.CFG_FILE_NAME_EXTS = cfg_dict['manifest_sec']['CFG_FILE_NAME_EXTS']
            config.CFG_TERM_PERC_TH = int(cfg_dict['manifest_sec']['CFG_TERM_PERC_TH'])

            # random_sec
            config.CFG_COMPR_RAND_TH = float(cfg_dict['random_sec']['CFG_COMPR_RAND_TH'])
            config.CFG_ENTR_RAND_TH = float(cfg_dict['random_sec']['CFG_ENTR_RAND_TH'])
            config.CFG_N_BYTES_2_RAND_CHECK = int(cfg_dict['random_sec']['CFG_N_BYTES_2_RAND_CHECK'])
            if config.CFG_N_BYTES_2_RAND_CHECK == -1:
                config.CFG_N_BYTES_2_RAND_CHECK = None

            config.CFG_COMPRESSED_CONTENT_MIN_LEN = int(cfg_dict['random_sec']['CFG_COMPRESSED_CONTENT_MIN_LEN'])

            # random_sec
            config.CFG_PATH_FOR_SIGNATURES = cfg_dict['random_sec']['magic_n_sec']['CFG_PATH_FOR_SIGNATURES']
            config.CFG_MAX_FILE_SIGNATURE_LENGTH = int(cfg_dict['random_sec']['magic_n_sec']['CFG_MAX_FILE_SIGNATURE_LENGTH'])

            # mail_sec
            config.CFG_SMTP_SSL = cfg_dict['mail_sec']['CFG_SMTP_SSL']
            config.CFG_SMTP_HOST = cfg_dict['mail_sec']['CFG_SMTP_HOST']
            config.CFG_SMTP_PORT = cfg_dict['mail_sec']['CFG_SMTP_PORT']
            config.CFG_SMTP_USER = cfg_dict['mail_sec']['CFG_SMTP_USER']
            config.CFG_SMTP_PWD = cfg_dict['mail_sec']['CFG_SMTP_PWD']

            pprint(cfg_dict)
        else:
            print("Problem with configuration file!")
    except FileNotFoundError:
        print("Problem with configuration file. Check the syntax and path.")
        sys.exit()
