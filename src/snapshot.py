import hashlib

import values
from utils import *
from subroutines import *
from logger import logger


def calculate_snapshot_hash():
    """
    Calculate md5 hash of a snapshot file
        (which only have the last snapshot and does not include ptr vars).
    """
    hash_md5 = hashlib.md5()
    # with open(values.file_snapshot + ".forhash", "rb") as f:
    with open(values.file_snapshot_processed, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.digest()


def parse_snapshots_from_file():
    """
    Parse the snapshot file to get snapshots.
    Also record the type of variables encountered.
    :returns: On success, a list of snapshots (one snapshot is one dict);
              on error, an empty list
    """
    result = list()
    if not os.path.isfile(values.file_snapshot_processed):
        return result
    with open(values.file_snapshot_processed, "r") as f:
        raw_lines = [ l.strip('\n') for l in f.readlines() ]
        raw_snapshot_lines = [list(y) for x, y
            in itertools.groupby(raw_lines, lambda z: z == "---") if not x]
        for one_snapshot_lines in raw_snapshot_lines:
            snapshot = {}
            for line in one_snapshot_lines:
                type, var, val = line.split()
                values.var_types[var] = type
                snapshot[var] = val
            result.append(snapshot)
    return result


def parse_last_typed_snapshot_from_file():
    """
    Parse the snapshot file, but only get the last snapshot with type.
    :returns: (1) The index of this last snapshot;
              (2) A dict, where key is var name, value is tuple (type, val)
    """
    result = dict()
    num_snapshots = 0
    if not os.path.isfile(values.file_snapshot_processed):
        return num_snapshots, result

    with open(values.file_snapshot_processed, "r") as f:
        lines = [ l.strip('\n') for l in f.readlines() ]
        lines = lines[:-1] # remove the very last delimeter
        # -1 means an imaginary delimeter line before the first snapshot
        last_delimeter_line = -1
        for line_num in range(len(lines)):
            if lines[line_num] == '---':
                num_snapshots += 1
                last_delimeter_line = line_num
        num_snapshots += 1 # since last snapshot does not end with '---'
        for line in lines[last_delimeter_line + 1:]:
            type, var, val = line.split()
            result[var] = (type, val)
    return num_snapshots, result


def collect_snapshots(pass_tests, fail_tests):
    pass_snapshots = list()
    fail_snapshots = list()
    all_tests = pass_tests + fail_tests
    for t in all_tests:
        _, new_pass, new_fail = collect_ss_from_one(t)
        pass_snapshots.extend(new_pass)
        fail_snapshots.extend(new_fail)
    return pass_snapshots, fail_snapshots


def collect_ss_from_one(test):
    """
    Collect snapshots from one input test.
    """
    pass_snapshots = list()
    fail_snapshots = list()
    logger.debug(f'Processing input {test}.')
    try:
        exec_result = run_bin_snapshot(test)
    except subprocess.TimeoutExpired:
        logger.debug(f'\tInput test {test} timeout. Skip.')
        return ExecResult.error, pass_snapshots, fail_snapshots
    snapshots = parse_snapshots_from_file()
    if not snapshots:
        logger.debug(f'\tInput test {test} produced no snapshot.')
        return ExecResult.error, pass_snapshots, fail_snapshots

    if exec_result == ExecResult.passing:
        pass_snapshots.extend(snapshots)
    if exec_result == ExecResult.failing:
        # for fail tests, only the last snapshot corresponds to a failure;
        # the previous snapshots did not cause crash
        fail_snapshots.append(snapshots[-1])
        pass_snapshots.extend(snapshots[:-1])

    return exec_result, pass_snapshots, fail_snapshots


def sanitize_snapshots(pass_ss, fail_ss):
    """
    The grand method for cleaning up snapshots.
    """
    pass_ss, fail_ss = remove_invalid_snapshots(pass_ss, fail_ss)
    pass_ss, fail_ss = remove_non_universal_variables_from_snapshots(pass_ss, fail_ss)
    return pass_ss, fail_ss


def remove_invalid_snapshots(pass_ss, fail_ss):
    """
    As a last sheild: remove invalid snapshots to prevent them
    from poluting other snapshots in preceeding steps
    """
    all_ss = pass_ss + fail_ss
    to_remove = []
    for ss in all_ss:
        if not ss:
            to_remove.append(ss)
    for empty_ss in to_remove:
        if empty_ss in pass_ss:
            pass_ss.remove(empty_ss)
        if empty_ss in fail_ss:
            fail_ss.remove(empty_ss)
    return pass_ss, fail_ss


def remove_non_universal_variables_from_snapshots(pass_ss, fail_ss):
    """
    Some ss may have more keys than others. This method only preserves keys that exist in all ss.

    Note that after values.candidate_variables are determined and the initial snapshots have been
    constrained to these variables, adding new snapshots to the pool followed by calling this
    method will make all the snapshots (old + new) have only vars in values.candidate_variables.
    """
    all_ss = pass_ss + fail_ss
    universal_keys = extract_common_vars_from_snapshots(all_ss)
    pass_ss = prune_snapshots_with_keys(pass_ss, universal_keys)
    fail_ss = prune_snapshots_with_keys(fail_ss, universal_keys)
    return pass_ss, fail_ss


def extract_common_vars_from_snapshots(snapshots):
    common_vars = set(snapshots[0].keys())
    for ss in snapshots:
        common_vars = common_vars.intersection(set(ss.keys()))
    return common_vars


"""
This section contains all heuristics to reduce # of variables in snapshot.
"""

NUM_VAR_THRESHOLD = 200

def decide_vars_to_include(pass_ss, fail_ss):
    """
    Determine the final vars to be included, given the sets of pass and fail snapshots.
    pre-condition: fail_ss is not empty.
    """
    num_vars = len(fail_ss[0].keys())
    # (1) remove uninteresting variables based on their values
    vars_to_include = select_by_removing_based_on_values(pass_ss, fail_ss)
    # (2) remove _GBase_ (they are not interesting in invariant inference)
    vars_to_include = select_by_removing_gbase(vars_to_include)
    # (3) remove _GSize_ if elem_size is too big
    vars_to_include = select_by_removing_unsupported_gsize(vars_to_include)
    top_level_vars = set(select_top_level_vars(vars_to_include))
    # (4) OPTIONAL, only done if use reduced snapshot (this is the default)
    if not values.unreduced:
        if (values.backend_choice == 'daikon' and num_vars > NUM_VAR_THRESHOLD) or values.backend_choice == 'cvc5':
            # select only sep score > 0
            top_sep_vars = select_based_on_sep_score(pass_ss, fail_ss)
            vars_to_include = [ v for v in top_sep_vars if v in vars_to_include ]
            # remove those with higher nesting depth, if still too many
            if len(vars_to_include) > NUM_VAR_THRESHOLD:
                vars_to_include = select_by_removing_deep_nesting_vars(vars_to_include)
        # elif values.backend_choice == 'cvc5':
        #     # select only sep score > 0
        #     top_sep_vars = select_based_on_sep_score(pass_ss, fail_ss)
        #     vars_to_include = [ v for v in top_sep_vars if v in vars_to_include ]
        #     # put back the top-level vars, this is to counter the aggressive-ness of always using separability score
        #     vars_to_include = list(set(vars_to_include).union(top_level_vars))
    # (3) Remove those with obviously irrelevant keywords
    vars_to_include = [ v for v in vars_to_include if not contain_irrelevant_keyword(v) ]

    return vars_to_include


def select_based_on_sep_score(pass_ss, fail_ss):
    """
    Rank variables in snapshots based on their separability scores.
    :param pass_ss: A list of dict, where each dict is a passing snapshot.
    :param fail_ss: A list of dict, where each dict is a failing snapshot.
    :returns: A list of variables (with positive separability scores)
              ranked by separabiltiy scores.
    """
    logger.debug(f'Reducing number of variables by separability score ...')
    # get all the benign values that a variable can take
    overall_benign_vals = {}
    for snapshot in pass_ss:
        for var_name in snapshot:
            if var_name not in overall_benign_vals:
                overall_benign_vals[var_name] = set()
            overall_benign_vals[var_name].add(snapshot[var_name])
    # get all the crash values that a variable can take
    overall_crash_vals = {}
    for snapshot in fail_ss:
        for var_name in snapshot:
            if var_name not in overall_crash_vals:
                overall_crash_vals[var_name] = set()
            overall_crash_vals[var_name].add(snapshot[var_name])
    # compute the separability score
    sep_scores = {}
    var_names = set(list(overall_benign_vals.keys()) + list(overall_crash_vals.keys()))
    for var_name in var_names:
        benign_values = set()
        if var_name in overall_benign_vals:
            benign_values = overall_benign_vals[var_name]
        crash_values = set()
        if var_name in overall_crash_vals:
            crash_values = overall_crash_vals[var_name]
        values = set.union(benign_values, crash_values)
        nonsep_values = set.intersection(benign_values, crash_values)
        sep_scores[var_name] = (len(values) - len(nonsep_values))/ (len(values)*1.0)
    sorted_vars = sorted(sep_scores.items(), reverse=True, key=lambda item: item[1])
    sorted_vars = sorted([ item[0] for item in sorted_vars if item[1] > 0 ])
    logger.debug(f'Variables after selection - #({len(sorted_vars)}) : {sorted_vars}')
    return sorted_vars


def select_top_level_vars(vars):
    """
    Select all the top-level vars (without . ->) from the given vars.
    """
    top_level = list()
    for v in vars:
        if '.' in v or '->' in v:
            continue
        top_level.append(v)
    logger.debug(f'Top-level variables - #({len(top_level)}) : {top_level}')
    return top_level


def select_by_removing_deep_nesting_vars(vars):
    """
    Snapshot logger by default go into depth of 3 to retrieve variables.
    This function provides an option to reducing the nesting depth.
    """
    logger.debug(f'Reducing number of variables by decreasing nested depth of structs ...')
    to_remove = list()
    for v in vars:
        dot_count = v.count('.')
        arrow_count = v.count('->')
        total_count = dot_count + arrow_count
        if total_count >= 2:
            to_remove.append(v)
    final_vars = [v for v in vars if v not in to_remove]
    return final_vars


def select_by_removing_unsupported_gsize(orig_vars):
    """
    For _GSize_ vars, if their corresponding elem_size is too big, and mutation needs to be done
    in the granularity of elem_size, the mutations cannot be performed correctly because of the
    ASAN redzone size limitations. For safety, these _GSize_ vars are removed.
    :param orig_vars: list of variables.
    :returns: new list of variables with unsupported _GSize_ removed.
    """
    if values.use_raw_size:
        # for raw size mode, mutation is done in granularity of bytes, so dont need to consider elem_size
        return orig_vars

    vars_to_remove = list()
    for var in orig_vars:
        if '_GSize_' in var:
            elem_size = values.gsize_to_elem_size.get(var)
            if elem_size is not None and elem_size >= 16:
                # only case where var should be removed
                vars_to_remove.append(var)

    return [ v for v in orig_vars if v not in vars_to_remove ]


def select_by_removing_gbase(orig_vars):
    """
    Since _GDiff_ is sufficient to represent ptr's relationship with the underlying object, there is
    no need for _GBase_ to be included when inferring patch invariant. Interesting patch invariants
    involving _GBase_ are already included by invariants with _GDiff_.
    """
    vars_to_remove = list()
    for var in orig_vars:
        if '_GBase_' in var:
            vars_to_remove.append(var)

    return [ v for v in orig_vars if v not in vars_to_remove ]


def select_by_removing_based_on_values(pass_ss, fail_ss):
    """
    Pre-condition: all snapshots should have the same keys.
    This method removes some variables based on their observed values:
    (1) If a _GDiff_ variable is always 0 across pass/fail, remove it.
        The case where p = base(p) would not give interesting invs based on _GDiff_.
    (2) If a _GSize_ variable is always 1 across pass/fail, remove it.
        A buffer whose size is always 1 is too small and usually uninteresting.
    """
    orig_keys = fail_ss[0].keys()
    keys_to_remove = list()
    all_ss = pass_ss + fail_ss

    logger.debug("Removing _GDiff_ vars that are always zero ...")
    for k in orig_keys:
        if not k.startswith("_GDiff_"):
            continue
        values_all_zero = True
        for ss in all_ss:
            val = int(ss[k])
            if val != 0:
                values_all_zero = False
                break
        if values_all_zero:
            keys_to_remove.append(k)

    logger.debug("Removing _GSize_ vars that are always one ...")
    for k in orig_keys:
        if not k.startswith("_GSize_"):
            continue
        values_all_one = True
        for ss in all_ss:
            val = int(ss[k])
            if val != 1:
                values_all_one = False
                break
        if values_all_one:
            keys_to_remove.append(k)

    final_keys = [ k for k in orig_keys if k not in keys_to_remove ]
    return final_keys


def likely_private_var(var):
    if "GSize" in var:
        return False
    if var.startswith("_") or var.startswith("*_"):
        return True
    if "._" in var or ".*_" in var:
        return True
    return False


def contain_irrelevant_keyword(var):
    irrelevant_keywords = ["raw", "version", "comment", "in.", "out.", "time", "date"]
    for keyword in irrelevant_keywords:
        if keyword in var:
            return True
    return False


def prune_snapshots_with_keys(snapshots, keys):
    """
    Only presever certains keys in a given list of snapshots.
    :params snapshots: A list of snapshots.
    :params keys: A set or list of keys to be preserved.
    :returns : Pruned snapshots.
    """
    for ss in snapshots:
        keys_to_remove = []
        for k in ss.keys():
            if k not in keys:
                keys_to_remove.append(k)
        for k in keys_to_remove:
            ss.pop(k)
    return snapshots
