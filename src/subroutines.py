import os
import shutil
import subprocess
import itertools
import enum
import signal
import operator

import values
from utils import *
from logger import logger


BIG_FILE_SIZE = 100
VALID_SNAPSHOT_STR = "snapshotfileisvalid"

def init_prog_cmd_with_input_file(file):
    inited_cmd = values.prog_cmd
    inited_cmd = inited_cmd.replace("<exploit>", file)

    return inited_cmd


def gdb_source_to_addr(source):
    """
    Get static ELF address from source line info.
    :param source: Source line info in the format <file.c:2021>
    :returns: The corresponding ELF static address.
    """
    cmd = ["gdb", values.bin_orig, "-ex", "info line " + source, "--batch"]
    cp = subprocess.run(cmd, stdout=subprocess.PIPE, encoding='utf-8')
    gdb_result = cp.stdout.strip('\n').split(' ')
    for i in range(len(gdb_result)):
        if gdb_result[i] == "address":
            return gdb_result[i+1]


def parse_prog_output_for_crash_line(out, rc):
    """
    Parse stderr of program execution with sanitizer, and returns useful information.
    :param out: stderr content
    :param rc: return code of the process
    :returns: (1) Error type
              (2) List of stack frames in crash trace. Each entry in the list is
                  a source code location, and the inner-most frame is at the
                  beginning of the list.
                  Only frames in the original binary is kept. Those that are obvious
                  to be in shared libraries are discarded.
              (3) Whether crash happens in E9Patch instrumentation.
                  This is important for correctly classifying execution result,
                  since the faulting instruction can be placed inside instrumentation.
    """
    # things to return
    bug_type = ""
    crash_lines = list()
    is_crash_in_e9 = False
    # what bug is this?
    is_asan = (rc == values.asan_exit_code)
    is_ubsan = (rc == values.ubsan_exit_code)
    if not is_asan and not is_ubsan: # no bug report - not a bug
        return bug_type, crash_lines, is_crash_in_e9

    # now either asan or ubsan crash - start parsing stderr
    if not isinstance(out, str):
        out = out.read() # io.TextIOWrapper
    splitted_out = out.split('\n')
    if len(splitted_out) == 0: # no output to parse
        return bug_type, crash_lines, is_crash_in_e9

    # Note: although we asked UBSAN to print stacktrace, sometimes stderr gets polutated when both
    # ASAN and UBSAN are enabled. This can happen when there is nested bug in same thread (both
    # ASAN and UBSAN trying to report something). Therefore, to handle the poluated outputs, we parse
    # UBSAN outputs conservatively, but just considering the single line reporting bug, instead of the
    # stack trace.

    # Case 1: UBSAN
    if is_ubsan:
        # ubsan bug type is hard to parse
        bug_type = "ubsan"
        is_crash_in_e9 = False
        info_line = ""
        for line in splitted_out:
            if 'runtime error' in line:
                info_line = line
        if not info_line: # somehow dont have this important line
            crash_lines = list()
        else:
            # content before "runtime error" is the location
            crash_loc = info_line.split('runtime error')[0]
            crash_lines = [ crash_loc ]

    # Case 2: ASAN
    elif is_asan:
        # (1) Get the stack frames in crash report - a list of locations in stack trace
        #     Also determines whether crash happens in E9 instrumentation
        # Purpose: store the processed # numbers. This is to only process the first
        # group of stack frames, since ASAN may print more than one groups (the other
        # groups indicate where the buffer was allocated)
        processed_frames = set()
        for line in splitted_out:
            if '#' not in line: # not a stack frame line
                continue
            words = line.split()
            curr_frame = words[0]
            if curr_frame in processed_frames:
                continue
            processed_frames.add(curr_frame)
            if '#0' in words and '(<unknown' in words and  'module>)' in words:
                # #0 ... (<unknown module>) sugguests that crash happened in E9 instrumentation
                is_crash_in_e9 = True
            if line[-1] != ')':
                # Take this as a hint for the current frame NOT being in a library,
                # so likely to be in the binary itself.
                crash_lines.append(words[-1])
        # (2) get the type of bug
        for line in splitted_out:
            if 'ERROR: AddressSanitizer:' in line:
                bug_type = line.split()[2]
                break

    return bug_type, crash_lines, is_crash_in_e9


def rebuild_project():
    """
    Rebuild project and move new binary to runtime dir.
    :returns: The return code after executing the build command.
    """
    os.chdir(values.dir_source)
    build_cmd = values.build_cmd
    logger.debug(f'Rebuilding project with the command: {build_cmd}')
    cp = subprocess.run(build_cmd, shell=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rc = cp.returncode
    logger.debug(f'Return code of build process is: {rc}')
    os.chdir(values.dir_root)
    if rc != 0:
        logger.debug(f'Rebuild process failed!')
    else:
        # move binary from build dir to runtime dir
        shutil.copy2(values.binary_full_path, values.bin_orig)
    return rc


def patch_for_afl():
    os.chdir(values.dir_lib)
    patch_cmd = ('./e9afl -o ' + values.bin_afl + ' ' + values.fix_loc + ' '
        + values.crash_loc + ' ' + values.bin_orig)
    logger.debug(f'Cmd for patch: {patch_cmd}')
    subprocess.run(patch_cmd, shell=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chdir(values.dir_root)


def patch_for_crash_at_location(addr):
    """
    :param addr: A address in hex.
    """
    os.chdir(values.dir_lib)
    patch_cmd = ('./e9tool --option --mem-ub=0x70000000 --option --loader-base=0x70007000 ' +
        '-M "addr= ' + addr + '" -A "exit(' + str(values.patch_exit_code) + ')" ' +
        values.bin_orig + ' -o ' + values.bin_crash)
    subprocess.run(patch_cmd, shell=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chdir(values.dir_root)


def patch_for_snapshot():
    os.chdir(values.dir_lib)
    patch_cmd = ('./e9tool --option --mem-ub=0x70000000 --option --loader-base=0x70007000 ' +
        '-M \'addr= ' + values.fix_loc + '\' -A \'call entry(base, static addr, state)@patch_hook\' ' +
        values.bin_orig + ' -o ' + values.bin_snapshot)
    logger.debug(f'Cmd for patch: {patch_cmd}')
    subprocess.run(patch_cmd, shell=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chdir(values.dir_root)


def patch_for_mutate(k, instructions):
    """
    Mutate kth snapshot with `instruction`.
    """
    os.chdir(values.dir_lib)
    # This version of e9patch does not support two instrumentations at one addr.
    # If fix_loc = crash_loc, the fix_loc instrumentation needs to add
    # certification statement.
    prefix_cmd = './e9tool --option --mem-ub=0x70000000 --option --loader-base=0x70007000 '
    if values.fix_loc == values.crash_loc: # one instrumentation
        two_loc_cmd = ('-M \'addr= ' + values.fix_loc + '\' -A \'call entry2(' +
        str(k) + ', 1, "' + instructions + '", base, static addr, state)@patch_hook\' ')
    else: # two separate instrumentations
        fix_loc_cmd = ('-M \'addr= ' + values.fix_loc + '\' -A \'call entry2(' +
            str(k) + ', 0, "' + instructions + '", base, static addr, state)@patch_hook\' ')
        crash_loc_cmd = ('-M \'addr= ' + values.crash_loc + '\' -A \'call entry3@patch_hook\' ')
        two_loc_cmd = fix_loc_cmd + crash_loc_cmd

    suffix_cmd = values.bin_orig + ' -o ' + values.bin_mutate
    patch_cmd = prefix_cmd + two_loc_cmd + suffix_cmd
    logger.debug(f'Cmd for patch: {patch_cmd}')
    subprocess.run(patch_cmd, shell=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chdir(values.dir_root)


def run_afl(mins):
    if not os.path.isdir(values.dir_afl_raw_input):
        os.mkdir(values.dir_afl_raw_input)
    if not os.path.isdir(values.dir_afl_raw_output):
        os.mkdir(values.dir_afl_raw_output)
    # prepare afl binary
    patch_for_afl()
    # prepare input seed
    shutil.copy2(values.file_exploit, values.dir_afl_raw_input)
    # actually run AFL
    os.chdir(values.dir_temp)
    afl_fuzz = os.path.join(values.dir_afl, "afl-fuzz")
    seed_size_bytes = os.path.getsize(values.file_exploit)
    # decide whether skip deterministic stage
    if values.afl_skip_deterministic is None: # config didnt say anything
        if seed_size_bytes > BIG_FILE_SIZE:
            afl_fuzz += ' -d' # skip deterministic stage
    else: # if config specifies this, follow what config says
        if values.afl_skip_deterministic:
            afl_fuzz += ' -d'
    afl_cmd = (afl_fuzz + ' -C -t 2000ms -m none -i ' + values.dir_afl_raw_input
        + ' -o ' + values.dir_afl_raw_output + ' ' + values.bin_afl)
    if values.input_from_stdin:
        inited_prog_cmd = init_prog_cmd_with_input_file("")
    else:
        inited_prog_cmd = init_prog_cmd_with_input_file("@@")
    afl_cmd += ' ' + inited_prog_cmd
    logger.debug(f'\tCmd to run: {afl_cmd}')
    afl_cmd = afl_cmd.split()
    try:
        subprocess.run(afl_cmd, timeout=mins*60)
    except subprocess.TimeoutExpired: # raised after child process terminates
        logger.info(f'\nFinished running AFL for {mins} mins.')
    os.chdir(values.dir_root)


def run_afl_normal(mins):
    if not os.path.isdir(values.dir_afl_raw_input_normal):
        os.mkdir(values.dir_afl_raw_input_normal)
    if not os.path.isdir(values.dir_afl_raw_output_normal):
        os.mkdir(values.dir_afl_raw_output_normal)
    # prepare afl binary
    patch_for_afl()
    # prepare input seed
    skip_deterministic = False
    for input in values.files_normal_in:
        seed_size_bytes = os.path.getsize(input)
        if seed_size_bytes > BIG_FILE_SIZE:
            skip_deterministic = True
        shutil.copy2(input, values.dir_afl_raw_input_normal)
    # actually run AFL
    os.chdir(values.dir_temp)
    afl_fuzz = os.path.join(values.dir_afl, "afl-fuzz")
    # decide whether skip deterministic stage
    if values.afl_skip_deterministic is None: # config didnt say anything
        if skip_deterministic:
            afl_fuzz += ' -d' # skip deterministic stage
    else: # if config specifies this, follow what config says
        if values.afl_skip_deterministic:
            afl_fuzz += ' -d'
    afl_cmd = (afl_fuzz + ' -t 500ms -m none -i ' + values.dir_afl_raw_input_normal
        + ' -o ' + values.dir_afl_raw_output_normal + ' ' + values.bin_afl)
    if values.input_from_stdin:
        inited_prog_cmd = init_prog_cmd_with_input_file("")
    else:
        inited_prog_cmd = init_prog_cmd_with_input_file("@@")
    afl_cmd += ' ' + inited_prog_cmd
    logger.debug(f'\tCmd to run: {afl_cmd}')
    afl_cmd = afl_cmd.split()
    try:
        subprocess.run(afl_cmd, timeout=mins*60)
    except subprocess.TimeoutExpired: # raised after child process terminates
        logger.info(f'\nFinished running AFL normal for {mins} mins.')
    os.chdir(values.dir_root)


def run_bin_orig_raw(input_file, timeout=5):
    """
    Run the original binary.
    :param input_file: Input for the binary.
    """
    os.chdir(values.dir_runtime)
    inited_prog_cmd = init_prog_cmd_with_input_file(input_file)
    cmd = values.bin_orig + ' ' + inited_prog_cmd
    if values.input_from_stdin:
        cmd += " < " + input_file
    try:
        proc = subprocess.Popen(cmd, start_new_session=True, shell=True,
            encoding='utf-8', universal_newlines=True, errors='replace',
            env=values.modified_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        # logger.warning(f'[run_bin_crash] Test {input_file} timeout.')
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        raise e
    logger.debug(f'Cmd to run: {cmd}')
    logger.debug(f'Return code from the run: {proc.returncode}')
    bug_type, crash_lines, _ = parse_prog_output_for_crash_line(proc.stderr, proc.returncode)
    os.chdir(values.dir_root)
    return bug_type, crash_lines, proc.returncode


def run_bin_orig(input_file):
    """
    Thin wrapper for run_bin_orig_raw.
    Returns ExecResult instead of the crash line.
    """
    bug_type, crash_lines, rc = run_bin_orig_raw(input_file)
    exec_result = classify_execution_return_value(bug_type, crash_lines, False, rc)
    logger.debug(f'Execution result: {exec_result}')
    return exec_result


def run_bin_crash(input_file, timeout=4):
    """
    Run a binary which was patched to crash at a certain location.
    :param input_file: Input for the binary.
    :returns: Return code of running the binary.
    """
    os.chdir(values.dir_runtime)
    inited_prog_cmd = init_prog_cmd_with_input_file(input_file)
    cmd = values.bin_crash + ' ' + inited_prog_cmd
    if values.input_from_stdin:
        cmd += " < " + input_file
    try:
        proc = subprocess.Popen(cmd, start_new_session=True, shell=True,
            encoding='utf-8', universal_newlines=True, errors='replace',
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        # logger.warning(f'[run_bin_crash] Test {input_file} timeout.')
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        raise e
    os.chdir(values.dir_root)
    return proc.returncode


def run_bin_snapshot(input_file, timeout=4):
    """
    Run a binary to obtain snapshot at a location.
    :param input_file: Input for the binary.
    :returns: instance of ExecResult.
    """
    os.chdir(values.dir_runtime)
    inited_prog_cmd = init_prog_cmd_with_input_file(input_file)
    cmd = values.bin_snapshot + ' ' + inited_prog_cmd
    if values.input_from_stdin:
        cmd += " < " + input_file
    # for snapshot run, also use sanitizer to ensure consistent behavior
    # for e.g., if a run does not crash, the fix location may be executed
    # more times after the "supposed" crash and snapshot would be different
    try:
        proc = subprocess.Popen(cmd, start_new_session=True, shell=True,
            encoding='utf-8', universal_newlines=True, errors='replace',
            env=values.modified_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        # logger.warning(f'[run_bin_crash] Test {input_file} timeout.')
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        raise e
    logger.debug(f'Cmd to run: {cmd}')
    logger.debug(f'Return code from the run: {proc.returncode}')
    bug_type, crash_lines, is_crash_in_e9 = parse_prog_output_for_crash_line(proc.stderr, proc.returncode)
    try:
        cleanup_snapshot_file()
    except Exception as e:
        raise e
    os.chdir(values.dir_root)
    exec_result = classify_execution_return_value(bug_type, crash_lines, is_crash_in_e9, proc.returncode)
    logger.debug(f'Execution result: {exec_result}')
    return exec_result


def run_bin_mutate(input_file, timeout=4):
    """
    Run a binary that mutates some program states at a location, and also dumps
    the snapshot at that location after mutation.
    :param input_file: Input for the binary.
    :returns: instance of ExecResult.
    """
    os.chdir(values.dir_runtime)
    inited_prog_cmd = init_prog_cmd_with_input_file(input_file)
    cmd = values.bin_mutate + ' ' + inited_prog_cmd
    if values.input_from_stdin:
        cmd += " < " + input_file
    try:
        proc = subprocess.Popen(cmd, start_new_session=True, shell=True,
            encoding='utf-8', universal_newlines=True, errors='replace',
            env=values.modified_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        # logger.warning(f'[run_bin_crash] Test {input_file} timeout.')
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        raise e
    logger.debug(f'Cmd to run: {cmd}')
    logger.debug(f'Return code from the run: {proc.returncode}')
    bug_type, crash_lines, is_crash_in_e9 = parse_prog_output_for_crash_line(proc.stderr, proc.returncode)
    try:
        is_valid_snapshot_file = cleanup_snapshot_file()
    except Exception as e:
        raise e
    os.chdir(values.dir_root)
    exec_result = classify_execution_return_value(bug_type, crash_lines, is_crash_in_e9, proc.returncode)
    if not is_valid_snapshot_file:
        # invalid snapshot file means that mutation cause the bug location
        # no longer reached; therefore should be unclassified
        exec_result = ExecResult.unclassified
    logger.debug(f'Execution result: {exec_result}')
    return exec_result


def cleanup_snapshot_file():
    """
    Raw snapshot files have following properties that we don't want:
    (1) Values of ptrs are in hex, not decimal.
    (2) Variable names not sorted.
    (3) Some ptrs have out of range values (due to effect of sanitizers).
    (4) _GDiff_ is absent, which is useful for modeling ptrs.
    (5) Has the magic string "snapshotfileisvalid" to certify validness.
    (6) Contains addrs, which may show duplicated aliases.
    (7) _GSize_ values are in bytes, change to #(elem) if necessary.

    This function does cleaning up, and produces two sorted files:
    (1) snapshot.out.processed: cleaned up snapshot file.
    (2) snapshot.out.forhash: only has the last snapshot and no ptrs; used only
                              for hash calculation.

    :returns: whether the original snapshot was certified as valid.
    """
    try: # wrap in `try` since file may not exist
        raw = open(values.file_snapshot_orig, "r")
        out = open(values.file_snapshot_processed, "w")
        out_forhash = open(values.file_snapshot_hash, "w")
    except Exception as e:
        logger.debug(f"Previous snapshot/mutate run did not produce snapshot file "
            f"{values.file_snapshot_orig}")
        raise e
    raw_lines = raw.readlines()
    raw_lines = [ l.strip('\n') for l in raw_lines ]
    # deal with the certification magic string
    is_valid_snapshot_file = VALID_SNAPSHOT_STR in raw_lines
    raw_lines = [ l for l in raw_lines if l != VALID_SNAPSHOT_STR ]
    # end
    raw_snapshot_lines = [list(y) for x, y
            in itertools.groupby(raw_lines, lambda z: z == "---") if not x]

    for snapshot_idx in range(len(raw_snapshot_lines)):
        # one iteration deals with one snapshot
        is_last_snapshot = (snapshot_idx == len(raw_snapshot_lines) - 1)
        # represent all the lines for one snapshot
        one_snapshot_lines = raw_snapshot_lines[snapshot_idx]
        snapshot_dict = dict() # name: (type, val), this holds the final entries
        snapshot_tuples = list() # temporary structure for processing
        # parse this one snapshot first
        for line in one_snapshot_lines:
            type, name, val, addr, elem_size = line.split()
            if type == '???': # unknown type
                continue
            if type == 'ptr':
                if val == '(nil)':
                    val = '0'
                else:
                    val = str(int(val, 16))
                # certain combinations of ASAN and UBSAN options can cause
                # garbage values for ptrs to be written to snapshot file
                if is_ptr_out_range(int(val)):
                    continue
            # store elem_size to dictionary to keep for later use
            elem_size_val = int(elem_size)
            if name.startswith('_GSize_') and elem_size_val != -1:
                values.gsize_to_elem_size.setdefault(name, elem_size_val)
            snapshot_tuples.append((name, type, val, addr))

        # remove duplicated aliases based on addr
        snapshot_tuples.sort(key=lambda element: (element[3], len(element[0]))) # sort by addr, then length of name
        seen_addrs = set()
        for name, type, val, addr in snapshot_tuples:
            if addr in seen_addrs:
                continue
            snapshot_dict[name] = (type, val)
            seen_addrs.add(addr)
        # _GSize_ and _GBase_'s parent may be alias that has been removed,
        # so remove them as well
        ghost_keys_to_remove = set()
        for name in snapshot_dict:
            if name.startswith('_GBase_') or name.startswith('_GSize_'):
                parent_name = name[7:]
                if parent_name not in snapshot_dict:
                    ghost_keys_to_remove.add(name)
        for k in ghost_keys_to_remove:
            snapshot_dict.pop(k)

        # add _GDiff_, which is the difference between ptr and its base
        gdiff_dict = dict()
        all_names = snapshot_dict.keys()
        for var_name in all_names:
            if not var_name.startswith('_GBase_'):
                continue
            parent_name = var_name[7:]
            if parent_name not in all_names:
                continue
            # found a pair of ptr and base(ptr)
            ptr_val = int(snapshot_dict[parent_name][1])
            base_ptr_val = int(snapshot_dict[var_name][1])
            diff_val = ptr_val - base_ptr_val
            diff_name = '_GDiff_' + parent_name
            gdiff_dict[diff_name] = ('int64', str(diff_val))
        snapshot_dict.update(gdiff_dict)

        # if _GSize_ should be ingradularity of elem_size, change it here
        if not values.use_raw_size:
            malformed_gsize_to_remove = set()
            for name in snapshot_dict:
                if not name.startswith('_GSize_'):
                    continue
                elem_size = values.gsize_to_elem_size.get(name)
                if elem_size is None:
                    # somehow this GSize does not have elem_size
                    # since we need elem_size to get accurate value, discard this GSize
                    malformed_gsize_to_remove.add(name)
                    continue
                # do division and get new GSize value
                old_val = int(snapshot_dict[name][1])
                new_val = old_val // elem_size
                # update snapshot_dict entry
                old_tuple = snapshot_dict[name]
                snapshot_dict[name] = (old_tuple[0], str(new_val))
            for k in malformed_gsize_to_remove:
                snapshot_dict.pop(k)

        # done with preparation, now print them to file
        all_names = sorted(snapshot_dict.keys())
        for var_name in all_names:
            type, val = snapshot_dict[var_name]
            str_rep = " {0: <6} {1: <40} {2: <15}\n".format(type, var_name, val)
            out.write(str_rep)
            if is_last_snapshot and type != 'ptr':
                out_forhash.write(str_rep)
        out.write('---\n')

    raw.close()
    out.close()
    out_forhash.close()
    # remove orig snapshot file, so that can catch error on next run (see if
    # a new orig snapshot file is produced)
    os.remove(values.file_snapshot_orig)
    return is_valid_snapshot_file


class ExecResult(enum.Enum):
    passing = 1
    failing = 2
    unclassified = 3
    error = 4


def classify_execution_return_value(bug_type, crash_lines, is_crash_in_e9, rc):
    """
    Classify execution result by parsing the crash info output from sanitizers.
    :param bug_type: A string like "FPE" indicating bug type.
    :param crash_lines: List of source code locations in the stack frame. First
                        list entry is the innermost frame.
    :param is_crash_in_e9: Whether crash happened in E9Patch instrumentation.
    :param rc: return code of the execution.
    """
    if rc != values.asan_exit_code and rc != values.ubsan_exit_code:
        # not terminated by sanitizers
        return ExecResult.passing

    if rc != values.exploit_exit_code:
        # crash is from a different sanitizer than that for exploit => a diff bug is triggered
        return ExecResult.unclassified

    if is_crash_in_e9:
        # crash happens in E9 instrumentation, determine solely baesd on bug type
        if bug_type == values.bug_type:
            return ExecResult.failing
        else:
            return ExecResult.unclassified

    if crash_lines:
        # was able to get some crash line info (i.e. output not terribly poluted)
        # can afford to compare bug type and crash location
        innermost_frame = crash_lines[0]
        if bug_type == values.bug_type and innermost_frame == values.exploit_crash_line:
            return ExecResult.failing

    # either (1) not able to get crash line info, cannot determine
    # or (2) there is crash line info, but it shows a different bug was triggered
    return ExecResult.unclassified


def extract_vars_from_constraint(constraint):
    """
    :param constraint: string reprensetation of a single constraint.
    """
    res = list()
    tokens = constraint.split()
    for token in tokens:
        if token in values.var_types.keys():
            res.append(token)
    return res
