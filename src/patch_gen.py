import os
import re
import shutil
import clang.cindex as cc
from typing import Optional

import values
from subroutines import *
from utils import *

"""
Takes in a patch invariant (string), a location, and generate a .patch file.
"""

class PatchGenerator(object):
    def __init__(self, inv):
        """
        fix line should be int
        """
        self.inv = inv
        self.fix_line = values.fix_line
        # a temporary location on disk to store the diff patch file
        self.patch_file_path = values.fix_file_path + ".patch"
        self.need_include_ghost = False
        self.sed_include_cmd = ""
        self.__backup_orig_file()
        self.__init_clang_parsing()
        self.__preprocess_inv()

    def __preprocess_inv(self):
        """
        If inv contains ghost variable, convert them to library calls that actually gets the value.
        """
        ghost_size_key = '_GSize_'
        ghost_diff_key = '_GDiff_'
        contains_ghost_size = ghost_size_key in self.inv
        contains_ghost_diff = ghost_diff_key in self.inv
        if not contains_ghost_size and not contains_ghost_diff:
            return

        # construct a sed command to insert #include
        self.need_include_ghost = True
        include_directive = "#include \"/home/yuntong/vulnfix/lib/ghost.c\""
        directive_line = self.__first_include_line_in_fix_file() + 1
        self.sed_include_cmd = "sed -i '" + str(directive_line) + " i " + include_directive + "' " + values.fix_file_path

        # now perform the actual replacement
        tokens = self.inv.split()
        updated_tokens = [ t for t in tokens ] # deep copy

        # each token can be _GSize_ or _GDiff_ => check each token and replace them if necessary
        for index, token in enumerate(tokens):
            if ghost_size_key in token: # this index should be replaced by proper size call
                orig_ptr_name = token[7:]
                replace_content = "generic_buffer_size(" + orig_ptr_name + ")"
                # generic_buffer_size returns raw size => now check whether need to make it #(elem)
                if not values.use_raw_size: # we are in #(elem) mode
                    elem_size = values.gsize_to_elem_size.get(token)
                    if elem_size is not None: # get elem_size OK
                        replace_content += " / " + str(elem_size)
                updated_tokens[index] = replace_content

            elif ghost_diff_key in token: # this index should be replaced by proper diff call
                orig_ptr_name = token[7:]
                base_call = "generic_buffer_base(" + orig_ptr_name + ")"
                replace_content = "( (void *)" + orig_ptr_name + " - " + base_call + " )"
                updated_tokens[index] = replace_content

        # replacement done - get the final inv in string
        self.inv = " ".join(updated_tokens)

    def __first_include_line_in_fix_file(self):
        """
        Check in the fix file, what is the line number for the first include directive.
        This is to have a safe place for us to insert our #include.
        """
        with open(values.fix_file_path, "r") as f:
            lines = f.readlines()
            for idx, line in enumerate(lines):
                if "#include" in line:
                    return idx + 1
        return 0 # prob wont happen

    def __init_clang_parsing(self):
        self.index = cc.Index.create()
        self.tu = self.index.parse(values.backup_file_path)

    def __backup_orig_file(self):
        shutil.copy2(values.fix_file_path, values.backup_file_path)


    def is_if_cond_line(self, line):
        return self.__is_keywords_in_line(line, ["if", "else"])

    def is_for_cond_line(self, line):
        return self.__is_keywords_in_line(line, ["for"])

    def is_while_cond_line(self, line):
        return self.__is_keywords_in_line(line, ["while"])

    def __is_keywords_in_line(self, line, keywords):
        """
        :returns: True if any word in `keywords` is contained in `line`.
        """
        # split by white space and ( )
        tokens = re.split('\s|\(|\)', line)
        for keyword in keywords:
            for token in tokens:
                if keyword == token:
                    return True
        return False


    def gen(self) -> Optional[str]:
        """
        Entry point for generating a patch, given a patch invariant.

        There are two strategies:
        1. Integrate into existing conditons.
        2. Generate a walkaround patch.
        For 1, there are also choices in how to do the integration:
        (1) Insert inv or negation of inv
        (2) When existing conditions are there, whether to prepend or append the
            new condition.
        Since there is no simple way of deciding them, the two choices are tried
        one by one until a patch that passes validation is produced.

        :returns: Path to a patch file if succeed; None if fail.
        """
        lines = list()
        with open(values.backup_file_path, "r") as f:
            lines = f.readlines()
        # check what the fix line actually is
        fix_line_index = self.fix_line - 1 ### 0-indexing!
        fix_line_content = lines[fix_line_index]
        if self.is_if_cond_line(fix_line_content) or self.is_while_cond_line(fix_line_content):
            patch_file = self.gen_patch_for_if_while(lines[fix_line_index:])
        elif self.is_for_cond_line(fix_line_content):
            patch_file = self.gen_patch_for_for(lines[fix_line_index:])

        if patch_file is None:
            # Now, either patch location is not condition,
            # or, patch location is condition, but failed to integrate inv into cond
            # generate walkaround fix with patch invariant
            patch_file = self.gen_patch_for_non_cond()

        if patch_file is None:
            # too bad, we tried all options but still fail
            logger.info("Patch generation unsuccessful. "
                "However, some patch invariants has been generated. "
                "Please manually generate a patch based on the patch invariant.")
        else:
            logger.info(f"Patch generation successful for this inv!")

        return patch_file


    def gen_patch_for_for(self, trailing_lines) -> Optional[str]:
        """
        Integrate the patch invariant into an existing for condition.
        :param trailing_lines: list of lines starting from the patch line.
        :returns: Path to a patch file if succeed; None if fail.
        """
        logger.debug("Trying to integrate patch invariant into for-condition ...")
        # determines the open/close ; position of the for-statement
        open_pos_line, open_pos_col, close_pos_line, close_pos_col = \
            self.__find_semicolon_positions(trailing_lines)
        # generate 4 sets of commands
        cmd_registry = list()
        negated_inv = "!(" + self.inv + ")"
        # (1) put patch invariant at the beginning
        #     for ( ... ; c ; ... ) => for ( ... ; inv && (c) ; ... )
        cmd_registry.append(self.__insert_at_beginning_of_condition(trailing_lines,
            self.inv, open_pos_line, open_pos_col, close_pos_line, close_pos_col))
        # (2) put patch invariant at the end
        #     for ( ... ; c ; ... ) => for ( ... ; (c) && inv ; ... )
        cmd_registry.append(self.__insert_at_end_of_condition(trailing_lines,
            self.inv, open_pos_line, open_pos_col, close_pos_line, close_pos_col))
        # (3) put negation of patch invariant at the beginning
        #     for ( ... ; c ; ... ) => for ( ... ; !(inv) && (c) ; ... )
        cmd_registry.append(self.__insert_at_beginning_of_condition(trailing_lines,
            negated_inv, open_pos_line, open_pos_col, close_pos_line, close_pos_col))
        # (4) put negation of patch invariant at the end
        #     for ( ... ; c ; ... ) => for ( ... ; (c) && !(inv) ; ... )
        cmd_registry.append(self.__insert_at_end_of_condition(trailing_lines,
            negated_inv, open_pos_line, open_pos_col, close_pos_line, close_pos_col))

        return self.enumerate_patch_options(cmd_registry)


    def enumerate_patch_options(self, cmd_options) -> Optional[str]:
        """
        Enumerate and try out the patch options, until a successful patch is seen.
        :param cmd_options: list of cmd lists, where each list represents one patch option.
        :returns: Path to a patch file, if any option succeeds;
                  None if all fail.
        """
        for cmd_list in cmd_options:
            restore_orig_patch_file()
            for cmd in cmd_list:
                os.system(cmd)
            if self.need_include_ghost:
                os.system(self.sed_include_cmd)
            is_valid_patch = self.rebuild_and_validate_patch()
            if is_valid_patch:
                patch_f_path = self.gen_final_patch_file()
                logger.debug("Successfully integrated patch into existing condition!")
                return patch_f_path

        logger.debug(f"Failed to integrate patch invariant into existing condition. "
            "Generating walkaround patch ...")
        return None


    def __find_semicolon_positions(self, trailing_lines):
        """
        :param trailing_lines: list of lines starting from the fix line.
        :returns: positions of the two semicolons in the for-clause.
        """
        res = list()
        for line_idx, line in enumerate(trailing_lines):
            for char_idx, char in enumerate(line):
                if len(res) == 4:
                    return res
                if char == ";":
                    res.append(line_idx)
                    res.append(char_idx)
        return [-1, -1, -1, -1]


    def gen_patch_for_if_while(self, trailing_lines) -> Optional[str]:
        """
        Integrate the patch invariant into an existing if/while condition expr.
        :param trailing_lines: list of lines starting from the patch line.
        :returns: Path to a patch file if succeed; None if fail.
        """
        logger.debug("Trying to integrate patch invariant into if/while-condition ...")
        # determines the open/close parenthesis position of the condition
        first_line = trailing_lines[0]
        open_pos_col = self.__find_opening_bracket_position(first_line)
        close_pos_line, close_pos_col = self.__find_closing_bracket_position(trailing_lines)

        # there are four types of possible patches; we prepare the changes first,
        # and then validate them one by one
        cmd_registry = list()
        negated_inv = "!(" + self.inv + ")"
        # (1) put patch invariant at the beginning
        #     if ( c ) => if ( inv && ( c ) )
        cmd_registry.append(self.__insert_at_beginning_of_condition(trailing_lines,
            self.inv, 0, open_pos_col, close_pos_line, close_pos_col))
        # (2) put patch invariant at the end
        #     if ( c ) => if ( ( c ) && inv )
        cmd_registry.append(self.__insert_at_end_of_condition(trailing_lines,
            self.inv, 0, open_pos_col, close_pos_line, close_pos_col))
        # (3) put negation of patch invariant at the beginning
        #     if ( c ) => if ( !(inv) && ( c ) )
        cmd_registry.append(self.__insert_at_beginning_of_condition(trailing_lines,
            negated_inv, 0, open_pos_col, close_pos_line, close_pos_col))
        # (4) put negation of patch invariant at the end
        #     if ( c ) => if ( ( c ) && !(inv) )
        cmd_registry.append(self.__insert_at_end_of_condition(trailing_lines,
            negated_inv, 0, open_pos_col, close_pos_line, close_pos_col))

        return self.enumerate_patch_options(cmd_registry)


    def __insert_at_end_of_condition(self, trailing_lines, insert_content,
        open_pos_line, open_pos_col, close_pos_line, close_pos_col):
        """
        Insert sth at the end of an condition clause.
            if ( c ) => if ( ( c ) && insert_content)
        :returns: list of sed commands that achieves this.
        """
        if close_pos_line == 0:
            same_open_close_line = True
        else:
            same_open_close_line = False

        open_line = trailing_lines[open_pos_line]
        close_line = trailing_lines[close_pos_line]
        if same_open_close_line:
            # opening ( and closing ) are on the same line
            new_line = (open_line[:open_pos_col+1] + "(" +
                open_line[open_pos_col+1:close_pos_col] + ") && " +
                insert_content + open_line[close_pos_col:])
            sed_cmd = self.__gen_sed_cmd(self.fix_line + open_pos_line, new_line)
            return [sed_cmd]
        else:
            # opening ( and closing ) are on diff line
            new_open_line = (open_line[:open_pos_col+1] + "(" + open_line[open_pos_col+1:])
            new_close_line = (close_line[:close_pos_col] + " ) && " + insert_content
                + ")" + close_line[close_pos_col:])
            sed_cmd_open = self.__gen_sed_cmd(self.fix_line + open_pos_line, new_open_line)
            sed_cmd_close = self.__gen_sed_cmd(self.fix_line + close_pos_line, new_close_line)
            return [sed_cmd_open, sed_cmd_close]


    def __insert_at_beginning_of_condition(self, trailing_lines, insert_content,
        open_pos_line, open_pos_col, close_pos_line, close_pos_col):
        """
        Insert sth at the beginning of an condition clause.
            if ( c ) => if ( insert_content && ( c ) )
        :returns: list of sed commands that achieves this.
        """
        if close_pos_line == 0:
            same_open_close_line = True
        else:
            same_open_close_line = False

        open_line = trailing_lines[open_pos_line]
        close_line = trailing_lines[close_pos_line]
        if same_open_close_line:
            # opening ( and closing ) are on the same line
            new_line = (open_line[:open_pos_col+1] + insert_content + " && ("
                + open_line[open_pos_col+1:close_pos_col] + ")" + open_line[close_pos_col:])
            sed_cmd = self.__gen_sed_cmd(self.fix_line + open_pos_line, new_line)
            return [sed_cmd]
        else:
            # opening ( and closing ) are on diff line
            new_open_line = (open_line[:open_pos_col+1] + insert_content
                + " && (" + open_line[open_pos_col+1:])
            new_close_line = close_line[:close_pos_col] + ")" + close_line[close_pos_col:]
            sed_cmd_open = self.__gen_sed_cmd(self.fix_line + open_pos_line, new_open_line)
            sed_cmd_close = self.__gen_sed_cmd(self.fix_line + close_pos_line, new_close_line)
            return [sed_cmd_open, sed_cmd_close]

    def __gen_sed_cmd(self, target_line, new_content):
        """
        Generate a sed cmd to replace the target_line content with new_content.
        :returns: a sed cmd for execution.
        """
        # sed -i '111s/^.*$/open_line/'
        # strip the new line char
        new_content = new_content.strip('\n')
        # escape all special characters in the context of sed, which are \ / & '
        new_content = new_content.replace("\\", "\\\\")
        new_content = new_content.replace("/", "\/")
        new_content = new_content.replace("&", "\&")
        new_content = new_content.replace("'", "'\\''")
        cmd = ("sed -i '" + str(target_line) + "s/^.*$/" + new_content + "/' "
            + values.fix_file_path)
        logger.debug(f'Generated sed command {cmd}.')
        return cmd

    def __find_opening_bracket_position(self, first_line):
        """
        :param first_line: the patch line itself.
        :return: col for the position of the opening `(`
        """
        for index, char in enumerate(first_line):
            if char == "(":
                return index
        return -1

    def __find_closing_bracket_position(self, trailing_lines):
        """
        :param trailing_lines: list of lines starting from patch line.
        :return: (line, col) for the position of the closing `)`
        """
        num_exceeding_left = 0
        pushed_first_left = False
        for line_idx, line in enumerate(trailing_lines):
            for char_idx, char in enumerate(line):
                if char == '(':
                    num_exceeding_left += 1
                    pushed_first_left = True
                elif char == ')':
                    num_exceeding_left -= 1
                if pushed_first_left and num_exceeding_left == 0:
                    # curr pos points to the closing )
                    return (line_idx, char_idx)
        # failed to find by matching parenthesis
        logger.debug('Warning! Failed to do parenthesis matching!')
        return (-1, -1)


    def gen_patch_for_non_cond(self) -> Optional[str]:
        """
        Used if the fix line does not contain a condition.
        In this case, following patch will be inserted before the fix line:
        +    if (!(patch invariant)) exit(1);

        :returns: Path to a patch file, if any option succeeds;
                  None if all fail.
        """
        logger.debug("Trying to generate walkaround patch ...")
        restore_orig_patch_file()
        patch = "    if (!(" + self.inv + ")) exit(1);"
        # insert patch into source code
        sed_cmd = "sed -i '" + str(self.fix_line) + "i\\" + patch + "' " + values.fix_file_path
        os.system(sed_cmd)
        if self.need_include_ghost:
            os.system(self.sed_include_cmd)
        is_valid_patch = self.rebuild_and_validate_patch()
        if is_valid_patch:
            patch_f_path = self.gen_final_patch_file()
            logger.debug("Successfully generated walkaround patch!")
        else:
            patch_f_path = None
            logger.debug(f"Failed to generate walkaround patch from patch invariant `{self.inv}`.")
        return patch_f_path


    def gen_final_patch_file(self) -> str:
        """
        Produce final .patch file.
        :returns: path to the generated patch file.
                  Clients should copy it if they want to preserve the content.
        """
        diff_cmd = ("diff -u " + values.backup_file_path + " "
            + values.fix_file_path + " > " + self.patch_file_path)
        os.system(diff_cmd)
        # shutil.copy2(self.patch_file_path, values.file_final_patch)
        return self.patch_file_path


    def rebuild_and_validate_patch(self):
        """
        :returns: True if patch has been validated against all inputs;
                  False if patch failed on some inputs, or the build failed.
        """
        # rebuild
        build_rc = rebuild_project()
        if build_rc != 0:
            logger.debug("Failed to rebuild project.")
            return False
        # validate
        for fail_input in values.all_fail_inputs:
            exec_result = run_bin_orig(fail_input)
            if exec_result == ExecResult.failing:
                logger.debug(f"Validation failed on input: {fail_input}.")
                return False
        logger.debug("Patch validation succeeded.")
        return True


    def get_function(self, root_cursor):
        func = ""
        for node in root_cursor.get_children():
            if node.kind != cc.CursorKind.FUNCTION_DECL:
                continue
            extent = node.extent
            if extent.start.line <= self.fix_line and extent.end.line >= self.fix_line:
                func = node.spelling
                break
        return func


    def extract_error_handling_code(self):
        return "exit(1)"
        # (1) find function containing fix line
        func = self.get_function(self.tu.cursor)
