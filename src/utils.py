import shutil

import values
from logger import logger

def flatten(iterable):
    """
    Flatten arbitrary nested lists, tuples, sets or ranges.
    https://stackoverflow.com/questions/47432632/flatten-multi-dimensional-array-in-python-3
    """
    if isinstance(iterable, (list, tuple, set, range)):
        for sub in iterable:
            yield from flatten(sub)
    else:
        yield iterable


def is_ptr_out_range(val):
    """
    Make sure that a ptr cannot be creater than 0x7fffffffffff
    """
    return val > 140737488355327


def is_unsigned_type(type):
    """
    Note: in the instrumentation, "signed char" is printed as "char",
          "unsigned char" is printed as "uint8_t".
    """
    return type.startswith('u')


def replace_patterns_in_str(str, old, new):
    """
    Replace all `old` in str with `new`.
    str is space separated.
    """
    tokens = str.split()
    updated_tokens = [ new if t == old else t for t in tokens ]
    new_str = " ".join(updated_tokens)
    return new_str


def restore_orig_patch_file():
    """
    Restore content of the original patch file.
    """
    shutil.copy2(values.backup_file_path, values.fix_file_path)


class Color:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    OFF = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def pretty_print_dict(dictionary, key_list):
    res = "{ "
    for key in sorted(dictionary):
        val = dictionary[key]
        if key in key_list:
            res += Color.WARNING + key + ":" + val + Color.OFF + ", "
        else:
            res += key + ":" + val + ", "
    res += "}\n"
    logger.debug(res)
