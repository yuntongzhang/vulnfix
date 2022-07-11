import os

from values import *
from utils import *
from subroutines import *

def validate_patch(patch_file):
    # get failing inputs first
    gather_failing_inputs()
    if not values.all_fail_inputs:
        return

    if os.path.isfile(values.backup_file_path):
        # restore project state if there is a backup file
        restore_orig_patch_file()
    else:
        # copy file to backup if there is not one
        shutil.copy2(values.fix_file_path, values.backup_file_path)


    # apply given patch file
    apply_patch_file(patch_file)
    # real validation
    is_ok = rebuild_and_validate()
    if is_ok:
        res_str = "PASS"
    else:
        res_str = "FAIL"
    print("Result for checking " + patch_file + " : " + res_str + "\n\n")


def gather_failing_inputs():
    if values.all_fail_inputs:
        return
    if not os.path.isdir(values.dir_afl_fail):
        return
    afl_fail = os.listdir(values.dir_afl_fail)
    values.all_fail_inputs = sorted([ os.path.join(values.dir_afl_fail, t) for t in afl_fail ])


def gather_passing_inputs():
    if values.all_pass_inputs:
        return
    if not os.path.isdir(values.dir_afl_pass):
        return
    afl_pass = os.listdir(values.dir_afl_pass)
    values.all_pass_inputs = sorted([ os.path.join(values.dir_afl_pass, t) for t in afl_pass ])


def apply_patch_file(patch_file):
    patch_cmd = "patch " + values.fix_file_path + " < " + patch_file
    os.system(patch_cmd)


def rebuild_and_validate():
        """
        :returns: True if patch has been validated against all inputs;
                  False if patch failed on some inputs, or the build failed.
        """
        # rebuild
        build_rc = rebuild_project()
        if build_rc != 0:
            print("Failed to rebuild project.\n")
            return False
        # validate
        for fail_input in values.all_fail_inputs:
            exec_result = run_bin_orig(fail_input)
            if exec_result == ExecResult.failing:
                print(f"Validation failed on input: {fail_input}.\n")
                return False
        print("Patch validation succeeded.\n")
        return True
