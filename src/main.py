import os
import shutil
import time
import random
import argparse
import configparser

import values
import snapshot_pool
from snapshot import *
from subroutines import *
from utils import *
from logger import *
from backend import *
from ce_refiner import CeRefiner
from patch_gen import PatchGenerator
from validate import validate_patch
import concfuzz


UNIQUE_TESTS_NEEDED = 100


def parse_config_and_setup_runtime(config_file):
    config = configparser.ConfigParser()
    with open(config_file, "r") as f:
        # put a fake section header at the beginning of config file
        config.read_string("[DEFAULT]\n" + f.read())
    config_dict = config['DEFAULT']
    # runtime-dir
    values.dir_runtime = config_dict['runtime-dir']
    if values.backend_choice == 'cvc5':
        values.dir_runtime = values.dir_runtime.replace('runtime', 'cvcback-runtime')
    elif values.concfuzz:
        values.dir_runtime = values.dir_runtime.replace('runtime', 'conc-runtime')
    elif values.aflfuzz:
        values.dir_runtime = values.dir_runtime.replace("runtime", "afl-runtime")
    if not os.path.isdir(values.dir_runtime):
        os.mkdir(values.dir_runtime)
    values.dir_afl_raw_input = os.path.join(values.dir_runtime, "afl-in")
    values.dir_afl_raw_output = os.path.join(values.dir_runtime, "afl-out")
    values.dir_afl_raw_input_normal = os.path.join(values.dir_runtime, "afl-in-normal")
    values.dir_afl_raw_output_normal = os.path.join(values.dir_runtime, "afl-out-normal")
    values.dir_afl_pass = os.path.join(values.dir_runtime, "afl-pass")
    values.dir_afl_fail = os.path.join(values.dir_runtime, "afl-fail")
    values.dir_seed_pass = os.path.join(values.dir_runtime, "seed-pass")
    values.dir_seed_fail = os.path.join(values.dir_runtime, "seed-fail")
    values.file_exploit = os.path.join(values.dir_runtime, "exploit")
    values.file_snapshot_orig = os.path.join(values.dir_runtime, "snapshot.out")
    values.file_snapshot_hash = os.path.join(values.dir_runtime, "snapshot.out.forhash")
    values.file_snapshot_processed = os.path.join(values.dir_runtime, "snapshot.out.processed")
    values.file_solver_in = os.path.join(values.dir_runtime, "input.sl")
    values.file_pass_ss_pool = os.path.join(values.dir_runtime, "pass-ss-pool")
    values.file_fail_ss_pool = os.path.join(values.dir_runtime, "fail-ss-pool")
    values.file_logging = os.path.join(values.dir_runtime, "vulnfix.log")
    values.file_final_patch = os.path.join(values.dir_runtime, "vulnfix.patch")
    values.file_result = os.path.join(values.dir_runtime, "vulnfix.result")
    # runtime-dir => daikon runtime files
    values.file_daikon_feasibility_traces = os.path.join(values.dir_runtime, "feasibility.dtrace")
    values.file_daikon_pass_traces = os.path.join(values.dir_runtime, "pass.dtrace")
    values.file_daikon_fail_traces = os.path.join(values.dir_runtime, "fail.dtrace")
    values.file_daikon_decl = os.path.join(values.dir_runtime, "daikon.decls")
    values.file_daikon_pass_inv = os.path.join(values.dir_runtime, "pass.inv")
    # binary
    values.binary_full_path = config_dict['binary']
    bin_name = os.path.split(values.binary_full_path)[1]
    if not values.resetbench:
        shutil.copy2(values.binary_full_path, values.dir_runtime)
    values.bin_orig = os.path.join(values.dir_runtime, bin_name)
    values.bin_afl = os.path.join(values.dir_runtime, bin_name + ".afl")
    values.bin_snapshot = os.path.join(values.dir_runtime, bin_name + ".snapshot")
    values.bin_mutate = os.path.join(values.dir_runtime, bin_name + ".mutate")
    values.bin_crash = os.path.join(values.dir_runtime, bin_name + ".crash")
    # exploit
    shutil.copyfile(config_dict['exploit'], values.file_exploit)
    # others
    values.prog_cmd = config_dict['cmd']
    values.fix_loc = config_dict['fix-location']
    values.crash_loc = config_dict['crash-location']
    values.dir_source = config_dict['source-dir']
    values.fix_file_rel_path = config_dict['fix-file-path']
    values.fix_file_path = os.path.join(values.dir_source, values.fix_file_rel_path)
    values.backup_file_path = os.path.join(os.path.dirname(values.fix_file_path), "fix-file-backup.c")
    values.fix_line = config_dict.getint('fix-line')
    values.build_cmd = config_dict['build-cmd']
    # OPTIONAL
    values.input_from_stdin = config_dict.getboolean('input-from-stdin', fallback=False)
    values.afl_skip_deterministic = config_dict.getboolean('afl-skip-deterministic', fallback=None)
    values.use_raw_size = config_dict.getboolean('use-raw-size', fallback=False)
    # OPTIONAL - multiple entries should be separated by ,
    if 'normal-in' in config_dict:
        normal_file_list = config_dict['normal-in'].split(',')
        for file in normal_file_list:
            values.files_normal_in.append(file.strip())

    # everything is set up, now set those that require running the binary
    if values.resetbench:
        # resetting benchmark just needs to recompile program, does not need to run it
        return
    # record original binary crashing line
    bug_type, crash_lines, rc = run_bin_orig_raw(values.file_exploit)
    values.bug_type = bug_type
    values.exploit_crash_line = crash_lines[0]
    values.exploit_exit_code = rc
    # fix_loc/crash_loc can be either file:line-num or hex addr in binary
    if not values.fix_loc.startswith("0x"):
        values.fix_loc = gdb_source_to_addr(values.fix_loc)
    if not values.crash_loc.startswith("0x"):
        values.crash_loc = gdb_source_to_addr(values.crash_loc)


def filter_store_initial_tests_and_snapshots(bound_time=True):
    """
    Perform filterings on the raw AFL output tests:
    (1) Must generate a distinct snapshot.
    (2) Must either be classified as passing or failing.
    :param bound_time: Whether set a time bound on how many tests to process.

    Also stores the test inputs in a dir, and stores snapshots into pool.
    """
    # prepare raw tests
    if not os.path.isdir(values.dir_afl_pass):
        os.mkdir(values.dir_afl_pass)
    if not os.path.isdir(values.dir_afl_fail):
        os.mkdir(values.dir_afl_fail)
    raw_fails_dir = os.path.join(values.dir_afl_raw_output, "crashes")
    raw_passes_dir = os.path.join(values.dir_afl_raw_output, "normals")
    raw_fails = [os.path.join(raw_fails_dir, t) for t in os.listdir(raw_fails_dir)]
    raw_passes = [os.path.join(raw_passes_dir, t) for t in os.listdir(raw_passes_dir)]
    if values.files_normal_in: # consider outputs from normal run as well
        raw_fails_dir_normal = os.path.join(values.dir_afl_raw_output_normal, "crashes")
        raw_passes_dir_normal = os.path.join(values.dir_afl_raw_output_normal, "normals")
        raw_fails.extend([os.path.join(raw_fails_dir_normal, t) for t in os.listdir(raw_fails_dir_normal)])
        raw_passes.extend([os.path.join(raw_passes_dir_normal, t) for t in os.listdir(raw_passes_dir_normal)])
    # preparation
    random.shuffle(raw_fails)
    random.shuffle(raw_passes)
    # also add the original exploit file to AFL dir and process it
    shutil.copyfile(values.file_exploit, os.path.join(values.dir_afl_fail, "exploit"))
    raw_fails = [values.file_exploit] + raw_fails
    patch_for_snapshot()

    all_pass_ss = list()
    all_fail_ss = list()

    logger.info(f'Starting to process AFL-generated inputs. This may take a while ...')

    num_pass, pass_ss, fail_ss, seen_hashes = process_raw_inputs(raw_passes, "pass", set(), bound_time=bound_time)
    all_pass_ss.extend(pass_ss)
    all_fail_ss.extend(fail_ss)
    num_fail, pass_ss, fail_ss, _ = process_raw_inputs(raw_fails, "fail", seen_hashes, bound_time=bound_time)
    all_pass_ss.extend(pass_ss)
    all_fail_ss.extend(fail_ss)

    logger.info('Finished processing AFL-generated inputs.')
    logger.debug(f'Num passing used: {num_pass}. Num failing used: {num_fail}.')
    post_process_of_initial_snapshots(all_pass_ss, all_fail_ss)


def process_raw_inputs(inputs, classification, seen_hashes, bound_time=True):
    """
    :param inputs: A list of inputs.
    :param classification: str of either "pass" or "fail".
    :param seen_hashes: A set of previously seen hashes.
    :param bound_time: Whether to set a time bound on how many tests to process.
    """
    time_budget = 3 * 60 # 3 mins for pass/fail
    unique_hashes = set(seen_hashes)
    pass_snapshots = list()
    fail_snapshots = list()
    num_saved = 0
    if classification == "pass":
        expected_result = ExecResult.passing
        destination_folder = values.dir_afl_pass
    else:
        expected_result = ExecResult.failing
        destination_folder = values.dir_afl_fail

    # start the real processing
    time_start = time.time()
    for t in inputs:
        if bound_time:
            if time.time() > time_start + time_budget and num_saved > 0:
                break
            if num_saved >= UNIQUE_TESTS_NEEDED:
                break
        exec_result, pass_ss, fail_ss = collect_ss_from_one(t)
        if exec_result != expected_result:
            continue
        curr_hash = calculate_snapshot_hash()
        if curr_hash in unique_hashes: # state already seen before
            continue
        unique_hashes.add(curr_hash)
        # add newly obtained snapshots
        pass_snapshots.extend(pass_ss)
        fail_snapshots.extend(fail_ss)
        # copy input to destination folder
        logger.debug(f"Found a usable {classification} input: {t}.")
        num_saved += 1
        file_name = classification + "-" + str(num_saved)
        shutil.copyfile(t, os.path.join(destination_folder, file_name))

    return num_saved, pass_snapshots, fail_snapshots, unique_hashes


def get_and_store_initial_snapshots(pass_tests, fail_tests):
    """
    Just gets snapshots from input tests.
    """
    patch_for_snapshot()
    pass_ss, fail_ss = collect_snapshots(pass_tests, fail_tests)
    post_process_of_initial_snapshots(pass_ss, fail_ss)


def post_process_of_initial_snapshots(pass_ss, fail_ss):
    """
    Should decide the final values.candidate_variables here.
    Perform the actual storing of snapshots.
    """
    pass_ss, fail_ss = sanitize_snapshots(pass_ss, fail_ss)
    vars_to_include = decide_vars_to_include(pass_ss, fail_ss)
    values.candidate_variables = set(vars_to_include)

    logger.debug(f'Number of vars in each snapshot : {len(values.candidate_variables)}')
    logger.debug(f'Final vars in each snapshot : {values.candidate_variables}')

    # prune snapshots to have only those variables to include
    pass_ss = prune_snapshots_with_keys(pass_ss, values.candidate_variables)
    fail_ss = prune_snapshots_with_keys(fail_ss, values.candidate_variables)
    snapshot_pool.add_new_snapshots(pass_ss, fail_ss)


def filter_test_do_not_reach_crash_loc(pass_tests, fail_tests):
    patch_for_crash_at_location(values.crash_loc)
    to_remove = []
    for t in pass_tests:
        try:
            return_code = run_bin_crash(t)
        except: # timeout
            to_remove.append(t)
            continue
        if return_code != values.patch_exit_code: # no reaching crash loc
            to_remove.append(t)
    pass_remains = [t for t in pass_tests if t not in to_remove]

    to_remove = []
    for t in fail_tests:
        try:
            return_code = run_bin_crash(t)
        except: # timeout
            to_remove.append(t)
            continue
        if return_code != values.patch_exit_code: # no reaching crash loc
            to_remove.append(t)
    fail_remains = [t for t in fail_tests if t not in to_remove]

    return pass_remains, fail_remains


def save_run_result(patch_invs, write_patch=False):
    with open(values.file_result, "w") as f:
        if len(patch_invs) == 1:
            f.write("SUCCESS (Exactly one patch invariant in the end) (Its correctness is not checked yet)\n")
        else:
            f.write("FAIL (More than one or no patch invariants in the end)\n")
        f.write("\nPatch Invariants:\n")
        f.write(str(len(patch_invs)) + "\n")
        f.write(f'{[i for i in patch_invs]}')
        if write_patch:
            f.write("\nGenerated Patch:\n")
            with open(values.file_final_patch, "r") as patch_f:
                content = patch_f.read()
                f.write(content)


def run_concfuzz_and_inference(backend):
    """
    Entry for invoking ConcFuzz and then running backend for patch invariant inference.
    """
    conc_dir = os.path.join(values.dir_runtime, "testcases")
    conc_seeds = [values.file_exploit] + values.files_normal_in
    concfuzz.start(conc_seeds, values.fix_loc, conc_dir)
    pass_dir = os.path.join(conc_dir, "pass")
    fail_dir = os.path.join(conc_dir, "fail")
    conc_pass = os.listdir(pass_dir)
    conc_fail = os.listdir(fail_dir)
    conc_pass = sorted([ os.path.join(pass_dir, t) for t in conc_pass])
    conc_fail = sorted([ os.path.join(fail_dir, t) for t in conc_fail])
    # logger.info(f'After 30 minutes of ConcFuzz, there are {len(conc_pass)} passing tests'
    #     f' and {len(conc_fail)} failing tests.')
    logger.info('Running generated inputs to collect snapshots ...')
    conc_pass, conc_fail = filter_test_do_not_reach_crash_loc(conc_pass, conc_fail)
    get_and_store_initial_snapshots(conc_pass, conc_fail)
    logger.info('Invoking backend on the collected snapshots to infer patch invariants ...')
    backend.generate_input_from_snapshots()
    candidate_exprs = backend.run()
    logger.info(f'Patch invariants from ConcFuzz - '
        f'#({len(candidate_exprs)}) : {[e for e in candidate_exprs]}.\n')
    # fini_logger()
    save_run_result(candidate_exprs)


def run_aflfuzz_and_inference(backend):
    """
    Entry for invoking AFL and then running backend for patch invariant inference.
    """
    if not values.files_normal_in: # only -C
        run_afl(values.time_budget)
    else: # additionally perform the normal run without -C
        run_afl(values.time_budget / 2)
        run_afl_normal(values.time_budget / 2)
    logger.info('Running generated inputs to collect snapshots ...')
    filter_store_initial_tests_and_snapshots(bound_time=False)
    logger.info('Invoking backend on the collected snapshots to infer patch invariants ...')
    backend.generate_input_from_snapshots()
    candidate_exprs = backend.run()
    logger.info(f'Patch invariants from aflfuzz - '
        f'#({len(candidate_exprs)}) : {[e for e in candidate_exprs]}.\n')
    # fini_logger()
    save_run_result(candidate_exprs)


def main():
    parser = argparse.ArgumentParser(description="Repair via fuzzing.")
    parser.add_argument('config_file', help='Path to the config file.')
    parser.add_argument('--budget', default=30, type=int,
                        help='Time budget in mins.')
    parser.add_argument('--backend', default='daikon',
                        choices=['daikon', 'cvc5'],
                        help='Backend for inferring invariants.')
    parser.add_argument('--unreduced', default=False, action='store_true',
                        help='Force to use original and unreduced snapshots.')
    parser.add_argument('--no-early-term', default=False, action='store_true',
                        help='disable early termination for snapshot fuzzing.')

    parser.add_argument('--concfuzz', default=False, action='store_true',
                        help='use concfuzz instead of snapshot fuzzing')
    parser.add_argument('--aflfuzz', default=False, action='store_true',
                        help='use afl-only fuzzing instead of snapshot fuzzing')
    parser.add_argument('--reset-bench', default=False, action='store_true',
                        help='reset benchmark subject for re-running it.')
    parser.add_argument('--vpatch', default='',
                        help='Pass in a patch file to validate correctness against AFL test suite.')

    parsed_args = parser.parse_args()
    config_file = parsed_args.config_file
    values.time_budget = parsed_args.budget
    values.backend_choice = parsed_args.backend
    values.unreduced = parsed_args.unreduced
    values.early_term = (not parsed_args.no_early_term)
    values.concfuzz = parsed_args.concfuzz
    values.aflfuzz = parsed_args.aflfuzz
    values.resetbench = parsed_args.reset_bench
    values.vpatch_file = parsed_args.vpatch

    parse_config_and_setup_runtime(config_file)
    init_logger()

    if values.vpatch_file:
        validate_patch(values.vpatch_file)
        return

    if values.resetbench:
        if not os.path.isfile(values.backup_file_path):
            # never created back up file before -> there is nothing to reset
            return
        # reset the benchmark program to vulnerable state, and simply return
        restore_orig_patch_file()
        rebuild_project()
        return

    if not os.path.isdir(values.dir_temp): # create temp dir to store runtime junks
        os.mkdir(values.dir_temp)

    if values.backend_choice == 'daikon':
        backend = DaikonBackend()
    elif values.backend_choice == 'cvc5':
        backend = CvcBackend()
    else:
        logger.warning(f'Backend {values.backend_choice} not supported. Aborting.')
        os.abort()

    logger.info('Finished parsing config file.')

    if values.concfuzz:
        run_concfuzz_and_inference(backend)
        return

    if values.aflfuzz:
        run_aflfuzz_and_inference(backend)
        return

    # Here is the main starting point of VulnFix
    logger.info('Starting VulnFix now!')
    time_start = time.time()
    time_end = time_start + values.time_budget * 60
    afl_time_budget = 10 # 10 mins

    # STEP (1): run AFL
    logger.info('Starting input-level fuzzing stage (AFL) ...')
    if not values.files_normal_in: # only -C
        run_afl(afl_time_budget)
    else: # additionally perform the normal run without -C
        run_afl(afl_time_budget / 2)
        run_afl_normal(afl_time_budget / 2)

    # STEP (2): get eligible tests from AFL outputs
    if values.backend_choice == 'daikon':
        filter_store_initial_tests_and_snapshots()
    elif values.backend_choice == 'cvc5':
        # for cvc, the time bottleneck is at inference, not processing inputs.
        # So, give all inputs to cvc so that variable reduction is more robust
        filter_store_initial_tests_and_snapshots(bound_time=False)
    afl_pass = os.listdir(values.dir_afl_pass)
    afl_fail = os.listdir(values.dir_afl_fail)
    values.all_pass_inputs = sorted([ os.path.join(values.dir_afl_pass, t) for t in afl_pass ])
    values.all_fail_inputs = sorted([ os.path.join(values.dir_afl_fail, t) for t in afl_fail ])

    # STEP (3): generate initial candidate invariant with backend
    backend.generate_input_from_snapshots()
    candidate_exprs = backend.run()
    logger.info(f'--- Initial patch invariants - '
        f'#({len(candidate_exprs)}) : {[e for e in candidate_exprs]} ---\n')

    # check whether there are some initial patch invariants
    if candidate_exprs:
        # STEP (4): refine candidate expr by mutating at fix location
        logger.info('Starting snapshot fuzzing stage ...')
        refiner = CeRefiner(candidate_exprs, values.all_pass_inputs, values.all_fail_inputs, backend)
        while True:
            if time.time() > time_end: # time budget exhausted
                logger.info('Total timeout reached.')
                break
            if values.early_term and refiner.reach_early_termination_criteria():
                logger.info('Repeatedly getting the same invariant. Stopping snapshot fuzzing now.')
                break
            curr_patch_invs = refiner.one_step_refinement(3)
            if not curr_patch_invs: # backend fails to produce any result
                break
        final_patch_invs = refiner.candidate_exprs # final result after snapshot fuzzing
    else:
        # initial patch invariants are empty, just return those without doing snapshot fuzzing
        final_patch_invs = candidate_exprs

    logger.info(f'--- Final patch invariants - '
        f'#({len(final_patch_invs)}) : {[e for e in final_patch_invs]} ---\n')

    is_patched = False
    if len(final_patch_invs) == 0:
        logger.info('Could not infer a patch invariant with the current invariant templates/grammar.')
    elif len(final_patch_invs) != 1:
        logger.info('More than one final patch invariant.')
    else: # got only 1 patch invariant
        if values.backend_choice == 'daikon':
            # only do patch generation for daikon backend to demonstrate the idea
            patch_inv = final_patch_invs[0]
            logger.info(f'Generating patch from the patch invariant `{patch_inv}` ...')
            try:
                generator = PatchGenerator(patch_inv)
                is_patched = generator.gen()
            except Exception as e:
                logger.info(f'Patch generation unsuccessful due to exception {e}.')
                is_patched = False

    # fini_logger()

    if is_patched:
        save_run_result(final_patch_invs, write_patch=True)
    else:
        save_run_result(final_patch_invs)


if __name__ == "__main__":
    main()
