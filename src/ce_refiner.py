import random

from ce_single_var import *
from subroutines import *
from snapshot import *

EARLY_TERM_THRESHOLD = 5

class CeRefiner(object):
    def __init__(self, exprs, inputs_pass, inputs_fail, backend):
        """
        :param exprs: list of candidate expressions (constraints)
        :param inputs_pass: list of passing test inputs
        :param inputs_fail: list of failing test inputs
        """
        self.round = 0
        self.candidate_exprs = exprs
        self.consecutive_same_count = 0
        # all the inputs given
        self.inputs_pass = inputs_pass
        self.inputs_fail = inputs_fail
        # record which inputs have not been used
        self.untouched_inputs_pass = set(inputs_pass)
        self.untouched_inputs_fail = set(inputs_fail)
        self.backend = backend
        self.__refresh_driver_tests()

    def __refresh_driver_tests(self):
        self.curr_pass = self.__pick_pass_input()
        self.curr_fail = self.__pick_fail_input()

    def __pick_pass_input(self):
        """
        Helper method to pick one pass input, prioritizing those not used before.
        """
        if not self.inputs_pass: # no pass input at all (this can happen if AFL did not generate any)
            return None
        if not self.untouched_inputs_pass: # all inputs have been used before
            return random.choice(self.inputs_pass)
        # randomly choose one untouched input
        chosen_one = random.choice(list(self.untouched_inputs_pass))
        self.untouched_inputs_pass.remove(chosen_one)
        return chosen_one

    def __pick_fail_input(self):
        """
        Helper method to pick one fail input, prioritizing those not used before.
        """
        if not self.untouched_inputs_fail: # all inputs have been used before
            return random.choice(self.inputs_fail)
        # randomly choose one untouched input
        chosen_one = random.choice(list(self.untouched_inputs_fail))
        self.untouched_inputs_fail.remove(chosen_one)
        return chosen_one

    def one_step_refinement(self, max_iter=6):
        """
        Refine current list of candidate exprs by generating counter examples to them.
        """
        pass_ss = list()
        fail_ss = list()
        # determine max_iter based on number of candidate expressions
        # this is to speed up filtering out many irrelevant invariants, and also
        # to explore more if there are only a few invariants
        num_inv = len(self.candidate_exprs)
        if num_inv > 25:
            max_iter = 1
        elif num_inv > 10:
            max_iter = 2
        elif num_inv > 5:
            max_iter = 3
        elif num_inv > 1:
            max_iter = 5
        else:
            max_iter = 10

        # generate new counter example snapshots
        for expr in self.candidate_exprs:
            ce_pass_ss, ce_fail_ss = self.__get_ce_for_single_constraint(expr, max_iter)
            pass_ss.extend(ce_pass_ss)
            fail_ss.extend(ce_fail_ss)

        snapshot_pool.add_new_snapshots(pass_ss, fail_ss)
        # build new backend inputs
        self.backend.generate_input_from_snapshots()
        # invoke backend
        candidate_exprs = self.backend.run()
        # check whether this backend run produces any result
        if not candidate_exprs:
            logger.info(f'Refinement round {self.round+1} produced no result.'
                f' The most recent patch invariants are: {[e for e in self.candidate_exprs]}.\n')
            return candidate_exprs

        # update refiner attributes
        self.round += 1
        if candidate_exprs == self.candidate_exprs:
            self.consecutive_same_count += 1
        else:
            self.consecutive_same_count = 0
        self.candidate_exprs = candidate_exprs
        self.__refresh_driver_tests()

        logger.info(f'--- Refinement round {self.round} finished. '
            f'Current patch invariants - #({len(self.candidate_exprs)}) : '
            f'{[e for e in self.candidate_exprs]} ---\n')
        return candidate_exprs


    def reach_early_termination_criteria(self):
        reached_count = self.consecutive_same_count >= EARLY_TERM_THRESHOLD
        only_one_expr = len(self.candidate_exprs) == 1
        return reached_count and only_one_expr


    def __get_ce_for_single_constraint(self, constraint, max_iter):
        """
        Generate counter example snapshots for a single constraint.
        """
        logger.info(f'Generating counter-examples for invariant {constraint}.')
        ce_pass_ss = list()
        ce_fail_ss = list()
        vars = extract_vars_from_constraint(constraint)
        # For each ce generator, fix a var for it
        for var in vars:
            logger.debug(f'Generating CE for invariant {constraint} and variable {var}.')
            try:
                if self.curr_pass:
                    ce_generator = CeGenerator(constraint, var, self.curr_pass, max_iter)
                    pass_ss, fail_ss = ce_generator.derive_counter_examples()
                    ce_pass_ss.extend(pass_ss)
                    ce_fail_ss.extend(fail_ss)
                if self.curr_fail:
                    ce_generator = CeGenerator(constraint, var, self.curr_fail, max_iter)
                    pass_ss, fail_ss = ce_generator.derive_counter_examples()
                    ce_pass_ss.extend(pass_ss)
                    ce_fail_ss.extend(fail_ss)
            except Exception as e:
                logger.debug(f"Skipping {var} due to exception {e} in CeGenerator constructor.")
                continue
        return ce_pass_ss, ce_fail_ss
