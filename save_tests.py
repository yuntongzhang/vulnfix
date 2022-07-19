"""
Script to save AFL generated test cases.
"""

import os
import json
import shutil

DIR_MAIN = "/home/yuntong/vulnfix"
FILE_META_DATA = os.path.join(DIR_MAIN, "meta-data.json")
DIR_DATA = os.path.join(DIR_MAIN, "data")
DIR_RUNTIME = "runtime"
DIR_SRC_PASS = os.path.join(DIR_RUNTIME, "afl-pass")
DIR_SRC_FAIL = os.path.join(DIR_RUNTIME, "afl-fail")
DIR_DEST = "test-suite"
DIR_DEST_PASS = os.path.join(DIR_DEST, "pass")
DIR_DEST_FAIL = os.path.join(DIR_DEST, "fail")

bug_list = list(range(1, 31))
extra_list = [ 35, 36, 37, 38, 39 ]
bug_list.extend(extra_list)

with open(FILE_META_DATA, 'r') as f:
    vulnerabilities = json.load(f)


for vulnerability in vulnerabilities:
    if int(vulnerability['id']) not in bug_list:
        continue

    id_str = vulnerability['id']
    bug_name = str(vulnerability['bug_id'])
    subject = str(vulnerability['subject'])

    print(f"\n=================== Running ({id_str}) {subject} {bug_name} ===================\n")

    vul_dir = os.path.join(DIR_DATA, subject, bug_name)
    # do real copying
    os.chdir(vul_dir)

    if os.path.isdir(DIR_SRC_PASS):
        os.makedirs(DIR_DEST_PASS, exist_ok=True)
        shutil.copytree(DIR_SRC_PASS, DIR_DEST_PASS, dirs_exist_ok=True)
    
    if os.path.isdir(DIR_SRC_FAIL):
        os.makedirs(DIR_DEST_FAIL, exist_ok=False)
        shutil.copytree(DIR_SRC_FAIL, DIR_DEST_FAIL, dirs_exist_ok=True)

    os.chdir(DIR_MAIN)
