import r2pipe
import json
import pprint
import tiktoken
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
import re
import argparse  # Import argparse library

def extract_hex_address(s):
    # Define a regular expression pattern to match a hexadecimal address
    pattern = r'0x[0-9a-fA-F]+'
    
    # Use the re.search() function to find the first occurrence of the pattern in the string
    match = re.search(pattern, s)
    
    # If a match is found, return the matched substring; otherwise, return None
    return match.group(0) if match else None

def extract_fcn_address(decompiled_code):
    # eg: extract 00401000 from fcn.00401000(blah
    # Define a regular expression pattern to match a hexadecimal address
    pattern = r'0x[0-9a-fA-F]+|([0-9a-fA-F]{8})'
    
    # Use the re.search() function to find the first occurrence of the pattern in the string
    match = re.search(pattern, decompiled_code)
    
    # If a match is found, return the matched substring; otherwise, return None
    return match.group(0) if match else None


def process_file(file_path):
    output_data = {}  # Dictionary to store the decompiled code and token count for each address
    # Strip json from file path
    stripped = file_path.replace("_capa.json", "")
    # This should be the binary, open it with r2pipe
    r2 = r2pipe.open(stripped)
    # Analyze the binary
    r2.cmd("aaaa")
    # Open the json file containing the capa hits
    with open(file_path) as f:
        data = json.load(f)
        # Iterate through the json
        for key in data:
            if key == "no address":
                output_data[key]["no address"] = data[key]
            # try:
            address = extract_hex_address(key)
            print(address)
            # if address is None:
            #     print("address is None")
            #     pass
            # Decompile the code at the key which is the address of the hits

            funct_address = r2.cmd(f"afn @ {address}")
            #extraction the function address from the decompile code
            fun_address = extract_fcn_address(funct_address)
            print(fun_address,"fun_address")
            #check to see if output_data already has this function
            if fun_address in output_data:
                print("fun_address, already in output_data")
                pass
            else:
                decompiled = r2.cmd(f"pdg @ {address}")
                # real    0m13.473s
                # user    0m0.377s
                # sys     0m0.057s
                # Get token count for decompiled code
                enc = tiktoken.encoding_for_model("gpt-4")
                encoded = enc.encode(decompiled)
                token_count = len(encoded)
                # Update the output_data dictionary
                output_data[fun_address] = {
                    "rules": data[key],
                    "decompiled_code": decompiled,
                    "token_count": token_count                        
                }
                print(output_data[fun_address])
            # except Exception as e:
            #     print("!!!!!!!!!!!!1 Exception: ", file_path)
            #     print(e)
                output_filename = os.path.splitext(file_path)[0] + "_decompiled.json"
                #output_filename = "/malware/w3/_decompiled.json"
                print(output_filename)
                with open(output_filename, "w") as outfile:
                    json.dump(output_data, outfile, indent=4)
                    print(f"Saved decompiled code to {output_filename}")
    print("closing r2")
    r2.close()

def main(input_directory):
    file_paths = []
    for root, _, files in os.walk(input_directory):
        for file in files:
            _, file_extension = os.path.splitext(file)

            if file_extension.lower() == '.json':
                file_paths.append(os.path.join(root, file))

    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(lambda file_path: process_file(file_path), file_paths)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process files in the input directory")
    parser.add_argument("input_directory", help="Path to the input directory containing files to process")
    args = parser.parse_args()

    main(args.input_directory)