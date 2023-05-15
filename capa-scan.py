import os
import json
import capa.main
import capa.rules
import capa.engine
import capa.helpers
from capa.rules import Rule, RuleSet
from capa.features.common import FORMAT_PE, FORMAT_DOTNET, String, Feature, Substring
from capa.render.result_document import RuleMetadata
from capa.render.result_document import ResultDocument
from concurrent.futures import ThreadPoolExecutor
import capa.exceptions
import argparse  # Import argparse library


def process_file(file_path):
    format_ = "auto"
    backend = "vivisect"
    _os = "windows"
    sigpaths = ["/home/gpu/code/capa/sigs/1_flare_msvc_rtf_32_64.sig"]
    rules = capa.main.get_rules(["/home/gpu/code/capa-rules-5.0.0/"])

    try:
        extractor = capa.main.get_extractor(file_path, format_, _os, backend, sigpaths)
        capabilities, _ = capa.main.find_capabilities(rules, extractor)
        output_data = {}
        for rule_name, matches in capabilities.items():
            for match in matches:
                memory_address = match[0]
                if str(memory_address) not in output_data:
                    output_data[str(memory_address)] = []
                output_data[str(memory_address)].append(rule_name)

        output_filename = os.path.splitext(file_path)[0] + "_capa.json"
        with open(output_filename, "w") as outfile:
            json.dump(output_data, outfile, indent=4)
    except capa.exceptions.UnsupportedFormatError:
        print("Unsupported format: ", file_path)
    except ValueError:
        print("ValueError: ", file_path)


def main(input_directory):

    file_paths = []
    for root, _, files in os.walk(input_directory):
        for file in files:
            file_paths.append(os.path.join(root, file))

    for file_path in file_paths:
        process_file(file_path)
        
    # with ThreadPoolExecutor(max_workers=2) as executor:
    #     executor.map(lambda file_path: process_file(file_path), file_paths)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process files in the input directory")
    parser.add_argument("input_directory", help="Path to the input directory containing files to process")
    args = parser.parse_args()

    main(args.input_directory)