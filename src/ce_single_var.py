from z3 import *

from subroutines import *
from snapshot import *
from utils import *
import snapshot_pool


class CeGenerator(object):
    """
    In charge of generating counter examples for one variable in one constraint.
    Uses a test-driven snapshot to fix values for other variables.
    """
    def __init__(self, constraint, variable, test, max_iter):
        """
        :param constraint: string representation of the constraint.
        :param variable: name of the variable for getting CE.
        :param test: test input for driving the execution.
        :param max_iter: number of times of solving constraints.
        """
        # fields that are actually set here
        self.raw_constraint = constraint
        self.variable = variable
        self.variable_value = None # original value of the target variable
        self.test = test
        self.max_iter = max_iter
        # fields as placeholder, which will be set later
        self.constraint = self.raw_constraint # this should only have one variable
        self.snapshot_num = 0 # which snapshot to mutate in this execution
        self.ins_prefix = ""
        self.exec_result = None
        self.orig_ptr_name = None
        self.base_ptr_val = None
        self.gsize_name = ""
        self.gsize_val = None
        self.gdiff_name = ""
        self.gdiff_val = None
        self.all_vars = None
        self.solver = None
        # set up some placeholder fields
        self.__init_helper()


    def __init_helper(self):
        """
        Perform various initializations:
        - store test execution result.
        - replace other variables in constraint with their values.
        - build initial mutation instruction with other variables.
        - build solver with initial constraint.
        """
        self.exec_result = run_bin_snapshot(self.test)
        if '_GDiff_' in self.variable or '_GSize_' in self.variable:
            self.__setup_extra_fields()
        self.__build_constraint_and_ins_prefix()
        self.__build_solver_with_constraint()


    def __setup_extra_fields(self):
        """
        Set up additional fields if our variable is a _GDiff_ or _GSize_
        pre-condition: `run_bin_snapshot` was called.
        """
        ptr_name = self.variable[7:]
        base_ptr_name = '_GBase_' + ptr_name
        self.gsize_name = '_GSize_' + ptr_name
        self.gdiff_name = '_GDiff_' + ptr_name
        _, typed_snapshot = parse_last_typed_snapshot_from_file()
        for var_name, type_val in typed_snapshot.items():
            _, val = type_val
            if var_name == base_ptr_name:
                self.orig_ptr_name = ptr_name
                self.base_ptr_val = int(val)
            if var_name == self.gsize_name:
                self.gsize_val = int(val)
            if var_name == self.gdiff_name:
                self.gdiff_val = int(val)


    def __build_constraint_and_ins_prefix(self):
        """
        pre-condition: `run_bin_snapshot` was called.
        """
        self.all_vars = extract_vars_from_constraint(self.raw_constraint)
        # parse last snapshot to get variable values
        self.snapshot_num, typed_snapshot = parse_last_typed_snapshot_from_file()
        for var_name, type_val in typed_snapshot.items():
            if var_name not in self.all_vars:
                continue
            _, val = type_val
            if var_name == self.variable:
                self.variable_value = int(val)
            else:
                # this var_name is to be replaced with its value
                self.constraint = replace_patterns_in_str(self.constraint, var_name, val)
                # also add this name-val pair to mutation instruction
                # reason: we are parsing from last snapshot (only last one was
                # distinguished as pass or fail), but mutating the first snapshot.
                # So, need to 'teleport' the values from last to first snapshot.
                # TODO: now we are mutating last snapshot, check if this still necessary?
                if var_name.startswith('_GSize_'):
                    final_name, final_val = self.__canonicalize_gsize_ins_pair(var_name, int(val))
                # elif var_name.startswith('_GDiff_'):
                #     final_name, final_val = self.__canonicalize_gdiff_ins_pair(var_name, int(val))
                else:
                    final_name = var_name
                    final_val = int(val)
                self.ins_prefix += final_name + "=" + str(final_val) + " "
        # check whether all variables except the target one have been replaced
        for token in self.constraint.split():
            if token in self.all_vars and token != self.variable:
                raise RuntimeError("No value found for var when building constraint", token)


    def __build_solver_with_constraint(self):
        """
        pre-condition: self.constraint only has 1 variable.
        """
        # python variables cannot take certain characters in C variables
        # thus, use 'x' to reprensent the (single) variable instead
        x = Int(self.variable)
        modified_constraint = replace_patterns_in_str(self.constraint, self.variable, 'x')
        # z3 does not recognize NULL
        modified_constraint = replace_patterns_in_str(modified_constraint, 'NULL', '0')
        # decl_str = self.variable + " = Int('" + self.variable + "')"
        # exec(decl_str)
        self.solver = Optimize()
        # set the objective function
        self.solver.minimize(self.__z3_abs(x - self.variable_value))
        if self.exec_result == ExecResult.passing:
            self.solver.add(Not(eval(modified_constraint)))
        elif self.exec_result == ExecResult.failing:
            self.solver.add(eval(modified_constraint))
        else:
            # TODO: change this to exception instead
            logger.warning('Should not have test that is unclassified during snapshot fuzzing! Aborting!')
            os.abort()

        # extra constriants - mutating buffer size
        if '_GSize_' in self.variable:
            # we should not mutate buffer size to be negative
            self.solver.add(x > 0)
            # buffer size should also be >= the corresponding GDiff, otherwise
            # the retreiving of new GSize will be directly reading redzone
            if self.gdiff_val:
                # added this check coz only ptrs have GDiff;
                # arrays have no GDiff, and their (implicit) GDiff is 0
                # NOW, consider two cases: _GSize_ is raw, or #(elem)
                if values.use_raw_size: # simple, since same unit as GDiff
                    self.solver.add(x >= self.gdiff_val)
                else: # need to *elem_size to get the raw size
                    elem_size = values.gsize_to_elem_size.get(self.variable)
                    if elem_size is not None:
                        self.solver.add(x * elem_size >= self.gdiff_val)

        # extra constraint - mutating ptrs (gdiffs)
        if '_GDiff_' in self.variable:
            self.solver.add(x >= 0)
            if self.gsize_val: # ptr should not go out of the current object
                if values.use_raw_size: # simple, since same unit
                    self.solver.add(x <= self.gsize_val)
                else:
                    elem_size = values.gsize_to_elem_size.get(self.gsize_name)
                    if elem_size is not None:
                        self.solver.add(x <= self.gsize_val * elem_size)
        # extra constraints - type constraints
        self.__add_type_constraint(x)


    def __add_type_constraint(self, x):
        t = values.var_types[self.variable]
        if is_unsigned_type(t):
            self.solver.add(x >= 0)
        if t == 'char': # signed char
            self.solver.add(x >= -128)
            self.solver.add(x <= 127)
        if t == 'uint8':
            self.solver.add(x <= 255)
        if t == 'uint32':
            self.solver.add(x <= 4294967295)
        if t == 'int32':
            self.solver.add(x >= -2147483648)
            self.solver.add(x <= 2147483647)


    # not in use
    def __canonicalize_gdiff_ins_pair(self, name, gdiff_val):
        """
        When sending mutate ins to E9, _GDiff_ needs to be converted back to ptr=ptr_val.
        pre-condition: `run_bin_snapshot` was called.
        :param name: name with _GDiff_ prefix.
        :param gdiff_val: value for _GDiff_.
        """
        ptr_name = name[7:]
        base_ptr_name = '_GBase_' + ptr_name
        _, typed_snapshot = parse_last_typed_snapshot_from_file()
        for var_name, type_val in typed_snapshot.items():
            _, val = type_val
            if var_name == base_ptr_name:
                gbase_val = int(val) # gbase is confirmed present, if gdiff is present
        new_ptr_val = gbase_val + gdiff_val
        return ptr_name, new_ptr_val


    def __canonicalize_gsize_ins_pair(self, name, gsize_val):
        """
        When sending mutate ins to E9, _GSize_ needs to be raw size in bytes.
        :param name: name with _GSize_ prefix.
        :param gsize_val: original value for _GSize_. Can be either in context of raw size or #(elem).
        """
        elem_size = values.gsize_to_elem_size.get(name)
        if elem_size is None: # somehow elem_size of this _GSize_ is unknown
            return name, gsize_val
        if values.use_raw_size:
            # in raw_size mode, nothing to be done
            return name, gsize_val
        else:
            # in #(elem) mode, get the raw size to send to E9
            raw_size = gsize_val * elem_size
            return name, raw_size


    def derive_counter_examples(self):
        """
        Attempts to derive counter examples (as snapshots) from this generator.
        Number of times for solving constraint and check execution result is
        bounded by self.max_iter
        """
        ce_pass_ss = list()
        ce_fail_ss = list()
        for _ in range(self.max_iter):
            # terminate if there is no model
            if self.solver.check() != sat:
                return ce_pass_ss, ce_fail_ss
            # generate model
            curr_model = self.__get_new_model()
            if not curr_model:
                # model is empty, z3 somehow can have sat together with empty model
                return ce_pass_ss, ce_fail_ss
            model_index = curr_model.decls()[0]
            new_val = curr_model[model_index].as_long()
            ##  generate full mutation instruction
            # for GDiff and GSize, solving is done with the original context, i.e. context of how
            # the snapshot values are defined. They need to be converted to what the E9 module can understand for mutation.
            # if '_GDiff_' in self.variable:
            #     final_name, final_val = self.__canonicalize_gdiff_ins_pair(self.variable, new_val)
            #     ins_tail = final_name + "=" + str(final_val)
            if '_GSize_' in self.variable:
                final_name, final_val = self.__canonicalize_gsize_ins_pair(self.variable, new_val)
                ins_tail = final_name + "=" + str(final_val)
            elif self.__mutation_should_be_malloc():
                # if this variable's mutation should be a malloc, ignore
                # the solver model since it's irrelevant
                ins_tail = self.variable + "=malloc1024"
            else:
                ins_tail = self.variable + "=" + str(new_val)
            curr_ins = self.ins_prefix + ins_tail
            # patch with mutation instruction and run binary
            patch_for_mutate(self.snapshot_num, curr_ins)
            logger.debug(f'Running binary with patch ins: {curr_ins}.')
            try:
                curr_res = run_bin_mutate(self.test)
            except subprocess.TimeoutExpired:
                logger.warning(f'\tTime out. Skip this mutation with {curr_ins}.')
                continue
            except Exception as e:
                logger.warning(f'\tException {e}. Skip this mutation with {curr_ins}.')
                continue
            snapshots = parse_snapshots_from_file()
            if not snapshots:
                logger.warning(f'\tNo snapshots. Skip this mutation with {curr_ins}.')
                continue

            # snapshots from 1 to (k-1) have been obtained before
            snapshots_from_kth = snapshots[self.snapshot_num-1:]

            # (1) check for counter-example
            if curr_res == self.exec_result: # counter-example found
                logger.debug(f'Counter-example snapshots have been found!')
                if curr_res == ExecResult.passing:
                    ce_pass_ss.extend(snapshots_from_kth)
                if curr_res == ExecResult.failing:
                    ce_fail_ss.append(snapshots_from_kth[-1])
                    ce_pass_ss.extend(snapshots_from_kth[:-1])
            # (2) check if still have new snapshots
            else:
                for idx, ss in enumerate(snapshots_from_kth):
                    if not snapshot_pool.is_new_snapshot(ss):
                        continue
                    # new snapshot, now check where to add it
                    logger.debug('New snapshots have been found!')
                    if curr_res == ExecResult.passing:
                        ce_pass_ss.append(ss)
                    if curr_res == ExecResult.failing:
                        if idx == len(snapshots_from_kth) - 1: # last one
                            ce_fail_ss.append(ss)
                        else:
                            ce_pass_ss.append(ss)

        return ce_pass_ss, ce_fail_ss


    def __get_new_model(self):
        """
        Get a new model which is different from all previous ones.
        """
        m = self.solver.model()
        # add negation of this model to the solver constraints
        self.solver.add([ f() != m[f] for f in m.decls() if f.arity() == 0])
        return m


    def __z3_abs(self, term):
        """
        Helper function to convert a z3 term to its absolute-value form.
        """
        return If(term >= 0, term, -term)


    def __mutation_should_be_malloc(self):
        if values.var_types[self.variable] != 'ptr':
            return False
        if self.exec_result == ExecResult.passing and '== NULL' in self.constraint:
            return True
        if self.exec_result == ExecResult.failing and '!= NULL' in self.constraint:
            return True
        return False
