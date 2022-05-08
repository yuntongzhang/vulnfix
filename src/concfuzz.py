import os
import time

from snapshot import calculate_snapshot_hash
from subroutines import *
from logger import *
import values

mutation_rounds = 1
# if a byte cause fix location no longer reached, sensitive=True
sensitivity_map = []
time_end = 0

# cumulative
pass_count = 0
fail_count = 0
hash_set = set()

SMALL_FILE_LEN = 30

def init_sensitivity_map(seed_bytes):
    """
    Perform mutation on each byte of the expliot input, to derive
    sensitivity map.
    """
    global sensitivity_map

    sensitivity_map = [] # reset
    temp_input_file = os.path.join(values.dir_runtime, "temp-input")
    exploit_len = len(seed_bytes)
    sensitivity_map = [False] * exploit_len

    logger.info('Starting to infer sensitivity map ...')
    logger.debug(f'Total input length (in bytes) is {exploit_len}')

    # for very small inputs, skip this step and just mutate all of them anw
    if exploit_len < SMALL_FILE_LEN:
        logger.debug(f'Exploit len ({exploit_len}) is too small, skip sensitivity map inference.')
        return

    for byte_pos in range(exploit_len):
        if time.time() > time_end:
            logger.warning(f'Timeout when doing init_sensitivity map.')
            break
        for _ in range(mutation_rounds):
            # form new input
            new_byte = os.urandom(1)
            new_input = seed_bytes[:byte_pos] + new_byte + seed_bytes[byte_pos+1:]
            with open(temp_input_file, "wb") as f:
                f.write(bytes(new_input))
            # check whether still reaches fix location
            try:
                return_code = run_bin_crash(temp_input_file)
            except:
                continue
            if return_code != values.patch_exit_code:
                # changing this byte cause the fix_loc not longer reached
                # print(f'pos {byte_pos} is sensitive!')
                sensitivity_map[byte_pos] = True
                break


def fuzz_with_sensitivity_map(seed_bytes, pass_dir, fail_dir):
    global sensitivity_map, pass_count, fail_count, hash_set

    logger.info('Starting to perform the actual fuzzing stage (for 30 mins) ...')

    temp_input_file = os.path.join(values.dir_runtime, "temp-input")
    round = 0
    # mutate each eligible byte
    while True:
        if time.time() > time_end:
            break
        round += 1
        logger.debug(f'Doing round {round} of ConcFuzz now ...')
        old_pass_count = pass_count
        old_fail_count = fail_count
        for byte_pos, is_sensitive in enumerate(sensitivity_map):
            if time.time() > time_end:
                break
            if is_sensitive:
                continue
            new_byte = mutate(seed_bytes[byte_pos])
            new_input = seed_bytes[:byte_pos] + new_byte + seed_bytes[byte_pos+1:]
            with open(temp_input_file, "wb") as f:
                f.write(bytes(new_input))
            # clean old snapshot files
            if os.path.exists(values.file_snapshot_orig):
                os.remove(values.file_snapshot_orig)
            if os.path.exists(values.file_snapshot_processed):
                os.remove(values.file_snapshot_processed)
            if os.path.exists(values.file_snapshot_hash):
                os.remove(values.file_snapshot_hash)

            # run this new input to get snapshot
            try:
                exec_result = run_bin_snapshot(temp_input_file)
            except:
                # print(f'skip due to exception in [run_bin_snapshot]')
                continue

            if not os.path.isfile(values.file_snapshot_hash):
                # does not reach fix location
                continue

            new_hash = calculate_snapshot_hash()
            if new_hash in hash_set:
                # does not produce new states
                continue
            hash_set.add(new_hash)

            if exec_result == ExecResult.passing:
                pass_count += 1
                shutil.copyfile(temp_input_file, os.path.join(pass_dir, "pass_" + str(pass_count)))
            elif exec_result == ExecResult.failing:
                fail_count += 1
                shutil.copyfile(temp_input_file, os.path.join(fail_dir, "fail_" + str(fail_count)))

        new_pass_count = pass_count - old_pass_count
        new_fail_count = fail_count - old_fail_count
        logger.debug(f'Rould {round} of ConcFuzz yields {new_pass_count} passing inputs, {new_fail_count} failing inputs.')


def mutate(orig_byte):
    """
    Perform a series of mutation on the original byte.
    """
    return os.urandom(1)


def read_seed_input(input):
    content = ""
    with open(input, "rb") as f:
        content = f.read()
    return bytearray(content)


def start(seed_inputs, fix_loc, test_dir):
    """
    Perform concentrated fuzzing.
    The output is a test suite reaching fix_loc.
    :param exploit_input: the one exploit input.
    :param fix_loc: a location in hex.
    :param test_dir: directory to place the generated test suite.
    """
    global time_end, sensitivity_map

    # prepare binaries
    patch_for_crash_at_location(fix_loc)
    patch_for_snapshot()

    # prepare directories
    pass_dir = os.path.join(test_dir, "pass")
    fail_dir = os.path.join(test_dir, "fail")
    if not os.path.isdir(pass_dir):
        os.makedirs(pass_dir)
    if not os.path.isdir(fail_dir):
        os.makedirs(fail_dir)
    # copy exploit input to fail dir
    shutil.copy2(values.file_exploit, fail_dir)

    # calc time budget
    num_seeds = len(seed_inputs)
    total_budget = values.time_budget * 60
    each_budget = total_budget / num_seeds

    # change to temp dir before actual running
    os.chdir(values.dir_temp)

    for seed in seed_inputs:
        logger.info(f'Processing seed input {seed} now ...')
        time_start = time.time()
        time_end = time_start + each_budget

        seed_bytes = read_seed_input(seed)
        init_sensitivity_map(seed_bytes)
        if time.time() > time_end:
            logger.warning(f'Timeout when processing seed {seed}.')
            break
        # how many bytes are not sensitive? (can be mutated)
        unsensitive_count = sum(not x for x in sensitivity_map)
        total_count = len(sensitivity_map)
        logger.info('Done with sensitivity map inference.')
        logger.info(f'{unsensitive_count}/{total_count} can be mutated in the input {seed}.')

        fuzz_with_sensitivity_map(seed_bytes, pass_dir, fail_dir)

    os.chdir(values.dir_root)
    logger.info(f'ConcFuzz ended. #(Passing inputs): {pass_count}. #(Failing inputs): {fail_count}.\n')
