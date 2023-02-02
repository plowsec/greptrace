from os import listdir
from os.path import isfile, getmtime, join
import os
import sys
import logging
from dataclasses import dataclass
from copy import deepcopy
logging.basicConfig(level=logging.DEBUG)
import re

@dataclass
class Chain:

    stack = []
    usages = {} # dict, keys are levels in the call stack tree, values are list of files containing the pattern
    current_pattern = ""
    depth= 0
    reachable = False
    source_params = set()
    source_functions = set()


    def __str__(self):

        res = ""
        res += self.stack[0] + "\n"
        for call in self.stack[1:]:
            res += "\t-> " + call + "\n"
        return res

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):

        return self.stack == other.stack


def get_translation_units(root_dir, whitelist=[]):

    tunits= []

    for (dirpath, dirs, files) in os.walk(root_dir):

        for filename in files:

            filename = os.path.join(dirpath, filename)

            if len(whitelist) > 0 and any(x in os.path.abspath(filename) for x in whitelist):

                if os.path.splitext(filename)[1] in [".jsp", ".java"]:
                    tunits += [filename]

            elif len(whitelist) == 0:
                if os.path.splitext(filename)[1] in [".jsp", ".java"]:
                    tunits += [filename]

        for folder in dirs:

            tunits += get_translation_units(folder, whitelist)

    return tunits

def find_file_containing_string(pattern, files, blacklist=[], concatenation_only=False):

    found_files = []

    for file in files:

        if file in blacklist:
            continue

        with open(file) as fl:
            found = next((l for l in fl if pattern in l), None) #find first occurrence in file
        if found:

            if concatenation_only:
                with open(file) as fl:
                    for line in fl:

                        if pattern in line:

                            if re.search(r"\".*\" ?\+", line, re.MULTILINE) is not None:
                                found_files += [file]
                                break
            else:

                found_files += [file]

    return found_files


def extract_class_name(file):

    class_name = ""
    if os.path.splitext(file)[1] == ".jsp":
        return os.path.basename(file)
    with open(file) as fl:
        for line in fl:

            if any(x in line for x in ["class ", "interface ", "enum "]):
                class_name = re.split("class |interface |enum", line)[1].split()[0]
                if class_name in os.path.basename(file):
                    return class_name


    if class_name == "":
        raise Exception("Cannot find class name")
    return class_name

def is_source(file, pattern):

    pattern_param = "getParameter("
    pattern_servlet = "HttpServletRequest"

    regex = (r"(?:(?:public|private|protected|static|final|native|synchronized|abstract|transient)+\s+)+[$_\w<>\[\]\s]*\s+([\$_\w]+)\([^\)]*\)?\s*\{?[^\}]*\}?\n")
    is_source_found = False
    with open(file) as fl:
        found = next((l for l in fl if pattern_param in l), None) #find first occurrence in file
        if found:
            # read the whole file again and locate the usage

            current_function = ""
            found_get_param = False
            found_pattern = False
            for line in fl:

                if (pattern_param in line or pattern_servlet in line) and current_function != "":
                    # found getparam
                    found_get_param = True
                if pattern in line and current_function != "":
                    found_pattern = True

                if found_pattern and found_get_param:
                    #logging.info(f"Pattern {pattern} was found in controller {current_function}")
                    is_source_found = True
                if re.search(regex, line) is not None:
                    matches = re.finditer(regex, line, re.MULTILINE)

                    found_get_param = False
                    found_pattern = False

                    match = next(matches)
                    current_function = match.group(1)
                    #logging.info(f"Current function = {current_function}")

    return is_source_found

def find_usages(chain, all_files, blacklist=[], depth=3, max_patterns=5):


    all_usages = find_file_containing_string(chain.current_pattern, all_files, blacklist=chain.stack)
    #logging.info(f"Usage detected in : {all_usages}")

    chain.depth += 1


    chain.usages[chain.depth] = all_usages
    chains = [chain]

    if chain.depth >= depth:
        return chains

    for file in all_usages[:max_patterns]:

        logging.info(f"Found '{chain.current_pattern}' pattern in {file}")
        class_name = extract_class_name(file)

        new_chain = deepcopy(chain)
        new_chain.current_pattern = class_name
        new_chain.stack += [file]

        if not is_source(file, chain.current_pattern):
            chains += find_usages(new_chain, all_files, blacklist + [file], depth=depth, max_patterns=max_patterns)
        else:
            new_chain.reachable = True
            chains += [new_chain]

    return chains

def extract_attack_surface(chain):

    current_params = set()
    params = set()
    file = chain.stack[-1]
    is_source_found = False
    functions = set()
    pattern_param = "getParameter("
    pattern_servlet = "HttpServletRequest"

    regex = (r"(?:(?:public|private|protected|static|final|native|synchronized|abstract|transient)+\s+)+[$_\w<>\[\]\s]*\s+([\$_\w]+)\([^\)]*\)?\s*\{?[^\}]*\}?\n")
    pattern = os.path.basename(chain.stack[-2]).split(".java")[0]

    with open(file) as fl:

        current_function = ""
        found_get_param = False
        found_pattern = False
        for line in fl:

            if "getParameter(\"" in line:
                param_name = line.split("getParameter(\"")[1].split("\")")[0]
                current_params.add(param_name)

            if (pattern_param in line or pattern_servlet in line) and current_function != "":
                # found getparam
                found_get_param = True
            if pattern in line and current_function != "":
                found_pattern = True

            if found_pattern and found_get_param:
                is_source_found = True
                functions.add(current_function)
            if re.search(regex, line) is not None:

                if is_source_found:
                    params = set(list(current_params) + list(params))
                    current_params.clear()
                    is_source_found = False
                matches = re.finditer(regex, line, re.MULTILINE)

                found_get_param = False
                found_pattern = False
                current_params.clear()

                match = next(matches)
                current_function = match.group(1)

    return params, functions


def build_callstack(folder_path, pattern="getWhere", restrict_to_file="", concatenation_only=False, depth=3, max_patterns=5, max_results=-1):

    all_files = get_translation_units(os.path.abspath(folder_path))
    files = find_file_containing_string(pattern, all_files, concatenation_only=concatenation_only)
    logging.info("Warning: debug on, only one file is analyzed")

    chains = []
    for file in files[:max_results]:

        # for testing only
        if restrict_to_file != "" and os.path.basename(file) != restrict_to_file:
            continue

        logging.info(f"Found pattern in {file}")
        class_name = extract_class_name(file)
        logging.info(f"Class name = {class_name}")
        chain = Chain()
        chain.stack = [file]
        chain.current_pattern = class_name
        chains += find_usages(chain, all_files, blacklist=chain.stack, depth=depth, max_patterns=max_patterns)

    uniq_chains = [v1 for i, v1 in enumerate(chains) if not any(v1 == v2 for v2 in chains[:i])]

    for chain in uniq_chains:
        if chain.reachable:
            logging.info(chain)
            params, functions = extract_attack_surface(chain)
            chain.source_params = params
            chain.source_functions = functions
            logging.info(f"You should fuzz these functions ({functions}), which have at least the following params: {params}")

    return uniq_chains

if __name__ == "__main__":

    build_callstack()
