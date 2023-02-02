import callstack
import j2ee_attack_surface

import argparse
import sys
import logging
import os

logging.basicConfig(level=logging.DEBUG)

LANGUAGE_EXTENSIONS = [".java", ".jsp"]

def pwn(webxml_path, source_dir, pattern="getWhere", restrict_to_file="", concatenation_only=False, depth=3, max_patterns=5, extensive=False, max_results=10):

    endpoints_standard = j2ee_attack_surface.parse(webxml_path)
    endpoints_beans = j2ee_attack_surface.parse_beans(webxml_path)
    chains = callstack.build_callstack(source_dir, pattern, restrict_to_file, concatenation_only, depth, max_patterns, max_results)

    print(endpoints_standard)
    print(endpoints_beans)
    print(chains)


    for chain in chains:

        class_name = os.path.splitext(os.path.basename(chain.stack[-1]))[0]
        for method in chain.source_functions:

            for bean in endpoints_beans:

                if class_name in bean.class_name and bean.method == method:
                    print(f"Found source. Fuzz {bean.url} with (non-exhaustive) params {chain.source_params} to reach from {class_name}.{method} to {os.path.basename(chain.stack[0])}")
                    print(f"\t{chain}")
                    break
            else:
                break
        else:
            if extensive:
                logging.info(f"Code path without obvious source: {class_name}.{chain.source_functions} with params {chain.source_params}\n{chain}")

if __name__ == "__main__":



    parser = argparse.ArgumentParser()


    parser.add_argument('-w', '--webxml', help="/path/to/web.xml")
    parser.add_argument('-d', '--dir', help="/path/to/source/directory (codebase to analyse)")
    parser.add_argument('-p', '--pattern', help="Pattern to look for")
    parser.add_argument('-f', '--file', help="Restrict the search to this file", required=False, default="")
    parser.add_argument('-c', '--concatenation', help='Restrict the search to functions which concatenate variables with strings (easy sql injections)', required=False, default=False, action="store_true")
    parser.add_argument("-l", "--depth", help="Max recursion level (default = 3)", default=3, type=int)
    parser.add_argument("-m", "--max", help="Max occurrences of patterns (prevent infinite loop or state explosion)", type=int, default=5)
    parser.add_argument("-e", "--extensive", help="Display results where the target URL (and controller) was not found in web.xml", default=False, action="store_true")
    parser.add_argument("-r", "--results", help="limit the number of results", type=int, default=-1)
    args = parser.parse_args()


    pwn(args.webxml, args.dir, args.pattern, restrict_to_file=args.file, concatenation_only=args.concatenation, depth=args.depth, max_patterns=args.max, extensive=args.extensive, max_results=args.results)
