import argparse
import os
import json
import sys
import shutil
from pathlib import Path

# DIR_MAIN = str(Path(__file__).parent.parent.resolve())
DIR_MAIN = "/home/yuntong/vulnfix"
FILE_MAIN = os.path.join(DIR_MAIN, "src", "main.py")
FILE_META_DATA = os.path.join(DIR_MAIN, "meta-data.json")
DIR_DATA = os.path.join(DIR_MAIN, "data")
# the place where to put result of running all vunerabilities
DIR_SUMMARY_RESULT = os.path.join(DIR_MAIN, "result")

# file/dir in individual vulnerability
FILE_CONFIG = "config"
FILE_INDIV_RESULT = "vulnfix.result"
DIR_RUNTIME = "runtime"
DIR_CVC_RUNTIME = "cvcback-runtime"
DIR_AFL_RUNTIME = "afl-runtime"
DIR_CONC_RUNTIME = "conc-runtime"

DEFAULT_LIST = list(range(1, 31)) # 30 entries in total


def setup_vul():
    os.system("./setup.sh")


def reset_vul(vul_dir):
    config_file = os.path.join(vul_dir, FILE_CONFIG)
    os.system(f"python3.8 {FILE_MAIN} --reset-bench {config_file}")


def collect_indiv_result(runtime_dir):
    indiv_result_file = os.path.join(runtime_dir, FILE_INDIV_RESULT)
    if not os.path.isfile(indiv_result_file):
        return ""
    f = open(indiv_result_file, "r")
    contents = f.read()
    f.close()
    return contents


def run_vulnfix_daikon(vul_dir):
    runtime_dir = os.path.join(vul_dir, DIR_RUNTIME)
    if os.path.isdir(runtime_dir):
        shutil.rmtree(runtime_dir)
    config_file = os.path.join(vul_dir, FILE_CONFIG)
    os.system(f"python3.8 {FILE_MAIN} {config_file}")
    return collect_indiv_result(runtime_dir)


def run_vulnfix_cvc(vul_dir):
    runtime_dir = os.path.join(vul_dir, DIR_CVC_RUNTIME)
    if os.path.isdir(runtime_dir):
        shutil.rmtree(runtime_dir)
    config_file = os.path.join(vul_dir, FILE_CONFIG)
    os.system(f"python3.8 {FILE_MAIN} --budget 180 --backend cvc5 {config_file}")
    return collect_indiv_result(runtime_dir)


def run_aflfuzz_induction(vul_dir):
    runtime_dir = os.path.join(vul_dir, DIR_AFL_RUNTIME)
    if os.path.isdir(runtime_dir):
        shutil.rmtree(runtime_dir)
    config_file = os.path.join(vul_dir, FILE_CONFIG)
    os.system(f"python3.8 {FILE_MAIN} --aflfuzz {config_file}")
    return collect_indiv_result(runtime_dir)


def run_concfuzz_induction(vul_dir):
    runtime_dir = os.path.join(vul_dir, DIR_CONC_RUNTIME)
    if os.path.isdir(runtime_dir):
        shutil.rmtree(runtime_dir)
    config_file = os.path.join(vul_dir, FILE_CONFIG)
    os.system(f"python3.8 {FILE_MAIN} --concfuzz {config_file}")
    return collect_indiv_result(runtime_dir)


def main():
    parser = argparse.ArgumentParser(description="Driver to run VulnFix on the VulnLoc dataset.")
    parser.add_argument('--setup', default=False, action='store_true',
                        help='Set up the vulnerabilities (not run).')
    parser.add_argument('--bug', action='append', type=int,
                        help='Specify which bug(s) to run. If nothing specified, all will be run.')
    # select which experiment to run.
    parser.add_argument('--daikon-exp', default=False, action='store_true',
                        help='Run experiments with VulnFix and daikon backend.')
    parser.add_argument('--cvc-exp', default=False, action='store_true',
                        help='Run experiments with VulnFix and cvc5 backend.')
    parser.add_argument('--aflfuzz-exp', default=False, action='store_true',
                        help='Run experiments with afl fuzz and inductive inference (daikon).')
    parser.add_argument('--concfuzz-exp', default=False, action='store_true',
                        help='Run experiments with concfuzz and inductive inference (daikon).')
    parser.add_argument('--reset', default=False, action='store_true',
                        help='Reset vulnerability binary to vulnerable stage. Useful if --daikon-exp was executed previously.')

    parsed_args = parser.parse_args()
    # do exacly one of these - setup, run, reset
    do_setup = parsed_args.setup
    do_reset = parsed_args.reset
    do_run = (not do_setup) and (not do_reset)
    if do_setup and do_reset:
        sys.exit("Can only use one of --setup and --reset!")

    selected_vul_list = parsed_args.bug
    # check which experiment should be invoked
    do_vulnfix_daikon = parsed_args.daikon_exp
    do_vulnfix_cvc = parsed_args.cvc_exp
    do_aflfuzz_daikon = parsed_args.aflfuzz_exp
    do_concfuzz_daikon = parsed_args.concfuzz_exp

    # make sure exactly one experiment is selected
    bool_sum = sum([do_vulnfix_daikon, do_vulnfix_cvc, do_aflfuzz_daikon, do_concfuzz_daikon])
    if (do_setup or do_reset) and (bool_sum != 0):
        print("WARNING: In setup/reset mode, specified experiment with be ignored.")
    if do_run and bool_sum != 1:
        sys.exit("Please make sure EXACTLY one experiment is selected!")
    if do_run: # decide going to run some experiments, so do some and setup
        if not os.path.isdir(DIR_SUMMARY_RESULT):
            os.mkdir(DIR_SUMMARY_RESULT)

    # decide on which vulnerabilities
    if selected_vul_list: # user speicified some
        vul_ids_to_run = selected_vul_list
    else: # user did not specify anything
        vul_ids_to_run = DEFAULT_LIST

    # decide on result file path
    result_file = "result"
    if do_vulnfix_daikon:
        result_file = "result-vulnfix-daikon"
    elif do_vulnfix_cvc:
        result_file = "result-vulnfix-cvc"
    elif do_aflfuzz_daikon:
        result_file = "result-aflfuzz-daikon"
    elif do_concfuzz_daikon:
        result_file = "result-concfuzz-daikon"
    result_file = os.path.join(DIR_SUMMARY_RESULT, result_file)

    with open(FILE_META_DATA, 'r') as f:
        vulnerabilities = json.load(f)

    if do_run:
        result_f = open(result_file, "w")

    for vulnerability in vulnerabilities:
        if int(vulnerability['id']) not in vul_ids_to_run:
            continue

        id_str = vulnerability['id']
        bug_name = str(vulnerability['bug_id'])
        subject = str(vulnerability['subject'])

        vul_dir = os.path.join(DIR_DATA, subject, bug_name)

        if do_setup:
            print(f"\n=================== Setting up ({id_str}) {subject} {bug_name} ===================\n")
            os.chdir(vul_dir)
            setup_vul()
            os.chdir(DIR_MAIN)

        if do_reset:
            print(f"\n=================== Resetting ({id_str}) {subject} {bug_name} ===================\n")
            os.chdir(DIR_MAIN)
            reset_vul(vul_dir)

        if do_run:
            print(f"\n=================== Running ({id_str}) {subject} {bug_name} ===================\n")
            result_f.write(f"=================== ({id_str}) {subject} {bug_name} ===================\n")
            os.chdir(DIR_MAIN)
            if do_vulnfix_daikon:
                result_content = run_vulnfix_daikon(vul_dir)
            elif do_vulnfix_cvc:
                result_content = run_vulnfix_cvc(vul_dir)
            elif do_aflfuzz_daikon:
                result_content = run_aflfuzz_induction(vul_dir)
            elif do_concfuzz_daikon:
                result_content = run_concfuzz_induction(vul_dir)
            result_f.write(result_content)
            result_f.write("\n\n")

    if do_run:
        result_f.close()
        print(f"\nResult summary written to file {result_file}.")

    print("\nFinished processing all vulnerabilities.")


if __name__ == "__main__":
    main()
