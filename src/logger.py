import logging
import os
import shutil

import values

logger = logging.getLogger('vulnfix')

def init_logger():
    logger.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    # console_handler.setLevel(logging.DEBUG)
    console_handler.setLevel(logging.INFO)

    debug_file_handler = logging.FileHandler(__debug_file_name())
    debug_file_handler.setLevel(logging.DEBUG)
    info_file_handler = logging.FileHandler(__info_file_name())
    info_file_handler.setLevel(logging.INFO)

    info_formatter = logging.Formatter("%(asctime)s %(message)s",
                                "%Y-%m-%d %H:%M:%S")
    debug_formatter = logging.Formatter("%(asctime)s [%(levelname)s] [%(funcName)s] %(message)s",
                                "%Y-%m-%d %H:%M:%S")

    console_handler.setFormatter(info_formatter)
    debug_file_handler.setFormatter(debug_formatter)
    info_file_handler.setFormatter(info_formatter)
    logger.addHandler(console_handler)
    logger.addHandler(debug_file_handler)
    logger.addHandler(info_file_handler)


def fini_logger():
    """
    May not perform as expected if not running on the benchmarks.
    """
    subj_dir = os.path.dirname(values.dir_runtime)
    shutil.copy2(__debug_file_name(), subj_dir)
    shutil.copy2(__info_file_name(), subj_dir)


def __debug_file_name():
    debug_file = values.file_logging + ".debug"
    if values.backend_choice == 'cvc5':
        debug_file += ".cvc5"
    if values.concfuzz:
        debug_file += ".conc"
    if values.aflfuzz:
        debug_file += ".afl"
    return debug_file


def __info_file_name():
    info_file = values.file_logging + ".info"
    if values.backend_choice == 'cvc5':
        info_file += ".cvc5"
    if values.concfuzz:
        info_file += ".conc"
    if values.aflfuzz:
        info_file += ".afl"
    return info_file
