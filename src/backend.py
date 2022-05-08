from abc import ABC, abstractmethod
import subprocess
import re
from sys import stdout

from logger import logger
from utils import *
from subroutines import *
import values
import snapshot_pool


class BackendBase(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def generate_input_from_snapshots(self):
        pass

    @abstractmethod
    def run(self):
        pass


"""
For debugging:
java -Xmx256m -cp thirdparty/daikon/daikon.jar daikon.Daikon --nohierarchy --conf_limit 1 --format java --config daikon-config
java -Xmx256m -cp thirdparty/daikon/daikon.jar daikon.tools.InvariantChecker
"""
class DaikonBackend(BackendBase):
    def __init__(self):
        super().__init__()

    def run(self):
        """
        :returns: A list of invariants, a list of variables appeared in invariants.
                If there is no output, returns two empty lists.
        """
        logger.info('Running Daikon for inference. This make take a while ...')
        # (1) generate invariants based on passing traces
        # Note: another thing to try is to set lower --conf_limit
        inv_cmd = ("java -Xmx256m -cp " + values.full_daikon + " daikon.Daikon "
            + "--nohierarchy --conf_limit 1 --format java --config " + values.file_daikon_config + " "
            + values.file_daikon_pass_traces + " " + values.file_daikon_decl + " -o "
            + values.file_daikon_pass_inv)
        subprocess.run(inv_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # (2) only get invariants that are violated by all failing traces
        filter_cmd = ("java -Xmx256m -cp " + values.full_daikon
            + " daikon.tools.InvariantChecker "
            + values.file_daikon_pass_inv + " " + values.file_daikon_fail_traces)
        cp = subprocess.run(filter_cmd, shell=True, encoding='utf-8',
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        # parse the output - only get invariants
        logger.debug(f'Raw daikon output is: {cp.stdout}')
        raw_lines = cp.stdout.strip('\n').split('\n')
        raw_lines = [ line.strip() for line in raw_lines ] # strip spaces
        # filter out meta lines (with [...] or ~~~) and empty lines
        inv_lines = [ line for line in raw_lines
                    if not line.startswith('[') and not line.startswith('~~~')
                    and line != "" ]
        invariants = self.__filter_daikon_invariants(inv_lines)
        invariants = self.__sanitize_daikon_invariants(invariants)
        invariants = self.__remove_duplicated_invariants(invariants)

        return invariants

    def __filter_daikon_invariants(self, invs):
        """
        Some daikon invariants are complicated to turn off from Daikon configs.
        We filter them out here.
        :param invs: A list of Daikon invariants.
        """
        filtered_invs = list()
        for inv in invs:
            if "has only one value" in inv:
                continue
            if "is boolean" in inv:
                continue
            filtered_invs.append(inv)
        return filtered_invs


    def __sanitize_daikon_invariants(self, invs):
        """
        Daikon output is formatted in java. Here we sanitize them to format that
        can be handled by z3 in python, and also can be use to generat patch in C.
        """
        sanitized_invs = list()
        java_long_pattern = re.compile("^[0-9]+L$")
        const_pattern = re.compile("^[0-9]+$")
        gdiff_pattern = re.compile("^_GDiff_.+$")
        for inv in invs:
            tokens = inv.split()
            # remove `L` from long integers
            tokens = [ t[:-1] if java_long_pattern.match(t) else t for t in tokens ]
            # remove UpperBound invariant if upper bound is very big
            if (len(tokens) == 3 and
                tokens[-2] == '<=' and
                const_pattern.match(tokens[-1]) and
                int(tokens[-1]) > 100):
                continue
            # remove LowerBound invariant if lower bound is very big or very small
            if (len(tokens) == 3 and
                tokens[-2] == '>=' and
                const_pattern.match(tokens[-1]) and
                (int(tokens[-1]) > 100 or int(tokens[-1]) < -100)):
                continue
            # remove x = a invariant if x is _GDiff_ (a pointer is of constant
            # offset is not interesting)
            if (len(tokens) == 3 and
                tokens[-2] == '==' and
                const_pattern.match(tokens[-1]) and
                gdiff_pattern.match(tokens[0])):
                continue
            # replace `null` with `NULL`
            tokens = [ 'NULL' if t == 'null' else t for t in tokens ]
            # form the new invariant
            new_inv = " ".join(tokens)
            sanitized_invs.append(new_inv)

        return sanitized_invs

    def __remove_duplicated_invariants(self, invs):
        """
        Daikon can produce semantically equivalent invariants.
        This method detects the duplicates and only keeps one of them.
        """
        # remove literal duplicates
        sanitized_invs = set(invs)
        # a >= 1, a != 0 are duplicated if a is unsigned type
        ge_one_pattern = re.compile("^([->\.\w]+) >= 1")
        eq_zero_pattern = re.compile("^([->\.\w]+) != 0")
        ge_one_vars = list()
        for inv in sanitized_invs:
            if ge_one_pattern.match(inv):
                ge_one_vars.append(ge_one_pattern.match(inv).group(1))
        inv_to_remove = set()
        for inv in sanitized_invs:
            if eq_zero_pattern.match(inv):
                var = eq_zero_pattern.match(inv).group(1)
                if var not in ge_one_vars:
                    continue
                if not is_unsigned_type(values.var_types[var]):
                    continue
                inv_to_remove.add(inv)
        sanitized_invs = list(sanitized_invs.difference(inv_to_remove))

        return sanitized_invs


    def generate_input_from_snapshots(self):
        """
        pre-condition: all snapshots should have the same keys (variables)
        """
        pass_ss = snapshot_pool.pass_ss
        fail_ss = snapshot_pool.fail_ss

        logger.debug(f'BEFORE BACKEND: # passing: {len(pass_ss)}; # failing: {len(fail_ss)}')
        common = "input-language C/C++\ndecl-version 2.0\nvar-comparability implicit\n"
        all_keys = (pass_ss + fail_ss)[0].keys()

        # (1) Build decl file
        decl_res = common
        decl_res += self.__convert_vars_into_decls(all_keys)
        with open(values.file_daikon_decl, "w") as f:
            f.write(decl_res)

        # (2) build dtrace files
        pass_res = common
        fail_res = common
        for snapshot in pass_ss:
            pass_res += "\n\n..fix_location():::ENTER\n"
            pass_res += "\n\n..fix_location():::EXIT\n"
            pass_res += self.__convert_single_snapshot_to_dtrace(snapshot, all_keys)
        with open(values.file_daikon_pass_traces, "w") as f:
            f.write(pass_res)
        for snapshot in fail_ss:
            fail_res += "\n\n..fix_location():::ENTER\n"
            fail_res += "\n\n..fix_location():::EXIT\n"
            fail_res += self.__convert_single_snapshot_to_dtrace(snapshot, all_keys)
        with open(values.file_daikon_fail_traces, "w") as f:
            f.write(fail_res)


    def __convert_vars_into_decls(self, vars):
        res = "\n\nppt ..fix_location():::ENTER\n"
        res += "\n\nppt ..fix_location():::EXIT\n"
        res += "  ppt-type point\n"
        for k in vars:
            res += "  variable " + k + "\n"
            # TODO: include field kind?
            res += "    var-kind variable\n"
            # we only differentiate between ptr and others;
            # for int types, use same dec-type so that daikon will compare them
            if values.var_types[k] == "ptr":
                res += "    rep-type hashcode\n"
                res += "    dec-type ptr\n"
            else:
                res += "    rep-type int\n"
                res += "    dec-type int\n"
            res += "    comparability 1\n"
            # TODO: include min max value based on type
        res += "\n\n"
        return res


    def __convert_single_snapshot_to_dtrace(self, snapshot, all_keys):
        res = ""
        for k in all_keys:
            res += k + "\n" # name
            res += snapshot[k] + "\n" # value
            res += "1\n" # modified? always 1
        return res


    # not used
    def run_daikon_for_feasibility():
        """
        :returns: list of invariants.
        """
        inv_cmd = ("java -Xmx256m -cp " + values.full_daikon + " daikon.Daikon "
            + "--nohierarchy --format java --config " + values.file_daikon_config + " "
            + values.file_daikon_feasibility_traces + " " + values.file_daikon_decl)
        cp = subprocess.run(inv_cmd, shell=True, encoding='utf-8',
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        raw_lines = cp.stdout.strip('\n').split('\n')
        raw_lines = [ line.strip() for line in raw_lines ] # strip spaces
        raw_lines = [ line for line in raw_lines if '_GBase_' in line ]
        # TODO: record feasibility constraints in some way
        print(raw_lines)

    # not used
    def convert_snapshots_to_feasibility_daikon_inputs(self, snapshots):
        """
        pre-condition: all snapshots should have the same keys (variables)
        """
        common = "input-language C/C++\ndecl-version 2.0\nvar-comparability none\n"
        all_keys = snapshots[0].keys()

        # (1) Build decl file
        decl_res = common
        decl_res += self.__convert_vars_into_decls(all_keys)
        with open(values.file_daikon_decl, "w") as f:
            f.write(decl_res)

        # (2) build one dtrace file
        dtrace_res = common
        for snapshot in snapshots:
            dtrace_res += "\n\n..fix_location():::ENTER\n"
            dtrace_res += "\n\n..fix_location():::EXIT\n"
            dtrace_res += self.__convert_single_snapshot_to_dtrace(snapshot, all_keys)
        with open(values.file_daikon_feasibility_traces, "w") as f:
            f.write(dtrace_res)

"""
For debugging:
./cvc5 --sygus-arg-relevant --sygus-eval-opt --sygus-grammar-norm --sygus-min-grammar --sygus-pbe --sygus-abort-size=5 --output-lang=cvc
"""
class CvcBackend(BackendBase):
    def __init__(self):
        pass


    def run(self):
        logger.info('Running cvc5 for inference. This make take a while ...')
        cmd = [values.full_cvc5, "--sygus-arg-relevant", "--sygus-eval-opt",
            "--sygus-grammar-norm", "--sygus-min-grammar",
            "--sygus-pbe", "--sygus-abort-size=5", "--output-lang=cvc",
            values.file_solver_in]
        try:
            max_time = 45 * 60 # 45 mins
            cp = subprocess.run(cmd, timeout=max_time, encoding='utf-8',
                    stdout=subprocess.PIPE)
        except subprocess.TimeoutExpired:
            logger.warning('cvc5 timeouts. Aborting backend and returning empty answer ...')
            return []

        # take second line, break at `BOOLEAN`, and strip the last `)`
        logger.debug(f'Raw cvc5 output is: {cp.stdout}')
        stdout_lines = cp.stdout.split('\n')
        if len(stdout_lines) <= 1 or "fail" in stdout_lines[0]:
            # no output, or output says "fail"
            logger.debug('cvc5 failed produce any output after terminating. Returning empty answer ...')
            return []
        candidate_expr = stdout_lines[1].split('BOOLEAN')[1][:-1]
        inv = self.__sanitize_cvc5_invariant(candidate_expr)
        return [inv]


    def __sanitize_cvc5_invariant(self, invariant):
        inv_tokens = invariant.strip().split()
        # change = to ==
        inv_tokens = [ '==' if t == '=' else t for t in inv_tokens ]
        temp_tokens = []
        # separate ( ) with adjacent tokens
        for t in inv_tokens:
            if '(' in t:
                two_sides = t.split('(', 1)
                if two_sides[0]:
                    temp_tokens.append(two_sides[0])
                temp_tokens.append('(')
                temp_tokens.append(two_sides[1])
            elif ')' in t:
                two_sides = t.split(')', 1)
                temp_tokens.append(two_sides[0])
                temp_tokens.append(')')
                if two_sides[1]:
                    temp_tokens.append(two_sides[1])
            else:
                temp_tokens.append(t)

        # move NOT into the operator
        if temp_tokens[0] == 'NOT' and temp_tokens[3] == '==':
            temp_tokens[3] = '!='
            temp_tokens.pop(0)

        # convert ptr >= 1 to ptr != NULL
        if (len(temp_tokens) == 3 and temp_tokens[0] in values.var_types
            and values.var_types[temp_tokens[0]] == "ptr"
            and temp_tokens[1] == ">=" and temp_tokens[2] == "1"):
            temp_tokens[1] = '!='
            temp_tokens[2] = 'NULL'

        # convert 1 <= ptr to ptr != NULL
        if (len(temp_tokens) == 3 and temp_tokens[2] in values.var_types
            and values.var_types[temp_tokens[2]] == "ptr"
            and temp_tokens[1] == "<=" and temp_tokens[0] == "1"):
            temp_tokens[0] = temp_tokens[2]
            temp_tokens[1] = '!='
            temp_tokens[2] = 'NULL'

        return " ".join(temp_tokens)


    def generate_input_from_snapshots(self):
        pass_ss = snapshot_pool.pass_ss
        fail_ss = snapshot_pool.fail_ss

        logger.debug(f'BEFORE BACKEND: # passing: {len(pass_ss)}; # failing: {len(fail_ss)}')
        res = "(set-logic LIA)\n"
        res += "(synth-fun f ("
        all_keys = sorted(list(fail_ss[0].keys()))
        for k in all_keys:
            res += "(" + k + " Int) "
        res += ") Bool\n"
        # declare the non-terminals
        res += "((Start Bool) (StartInt Int))\n"
        # Boolean non-terminal
        res += "((Start Bool(\n"
        res += "(not Start)\n"
        res += "(and Start Start)\n"
        res += "(or Start Start)\n"
        res += "(<= StartInt StartInt)\n"
        res += "(>= StartInt StartInt)\n"
        res += "(= StartInt StartInt)))\n"
        # Int non-terminal
        res += "(StartInt Int (\n"
        # constant values
        # for i in range(17):
        for i in range(100):
            res += str(i) + "\n"
        # some power-of-two and type boundary values
        # res += "32\n50\n64\n100\n128\n256\n512\n1024\n2048\n4096\n8192\n16384\n"
        res += "100\n128\n256\n512\n1024\n2048\n4096\n8192\n16384\n"
        res += "32767\n65535\n1048575\n2147483647\n4294967295\n"
        # parameters
        for k in all_keys:
            res += k + "\n"
        # arithmetic operators
        res += "(+ StartInt StartInt)\n"
        res += "(- StartInt StartInt)\n"
        res += "(* StartInt StartInt)\n"
        res += "))))\n"

        # constraints
        for ss in pass_ss:
            res += self.__convert_single_snapshot_to_constraint(ss, all_keys, "true")
        for ss in fail_ss:
            res += self.__convert_single_snapshot_to_constraint(ss, all_keys, "false")
        res += "\n(check-synth)\n"
        with open(values.file_solver_in, "w") as f:
            f.write(res)

        return all_keys


    def __convert_single_snapshot_to_constraint(self, snapshot, all_keys, return_val):
        """
        Helper method.
        """
        res = "(constraint (= (f"
        for k in all_keys:
            value = snapshot[k]
            if '-' in value:
                value = "(- " + value[1:] + ")"
            res += " " + str(value)
        res += ") " + return_val + "))\n"
        return res
