import sys

import shutil, subprocess
import json
from unittest import result
import remediations

from colorama import Fore, Style, init

from utils import *
import re


def run():

    installed, version = check_inspec_installed()
    if not installed:
        print_not_installed_message()
        sys.exit(1)
    else:
        print("InSpec is installed with version ", version)

        scan_completed = False

        while True:
            print("")
            print_prompt()
            choice = input("> ")

            if choice == "1" or choice == "scan":
                run_scan()
                scan_completed = True

            if choice == "2" or choice in ["remediate", "fix", "resolve"]:
                if scan_completed:
                    run_remediate_choice()
                else:
                    print("You must initiate a scan before attempting to remediate")

            if choice == "3" or choice == "exit":
                exit_from_prompt()

def run_user_choice(choice):
    if choice == "2" or choice in ["remediate", "fix", "resolve"]:
        print() # Add prompt to show potential configs to remediate

    if choice == "3" or choice == "exit":
        exit_from_prompt()

    else:
        print("Invalid choice, please try again")

def run_remediate_choice():
    # TODO: Implement functionality to parse controls.json file and run the correct function/remediation
    # Acquire the list of all available remediations
    # Print available remediations

    print("Enter 'x' or 'exit' to exit")
    available_remediations = get_available_remediations()
    print_available_remediations(available_remediations)


    remediation_lookup = {
        remediation['function'].__name__: remediation['function']
        for remediation in available_remediations
    }

    # Ask for user input
    # While True
        # if user input equals 'x' or 'exit' then break out of the function
        # validate user input against available remediations:
            # If the function exists, the run it.
            # If the function doesn't exist, then notify the user and ask for input again

    while True:
        choice = input("> ")
        if choice in ['x', 'exit', '']:
            break
        func = remediation_lookup.get(choice)

        if func:
            func()
        else:
            print(f"Error: Remediation {choice} not found")

def run_scan():
    print("Starting scan...")
    with open("config/config.json") as config_file:
        config = json.load(config_file)
        profile = config["inspec_profile_linux"]
        scan_cmd = ["inspec", "exec", "https://github.com/dev-sec/linux-baseline", "--reporter", "json", "--chef-license", "accept"]

        scan_result = subprocess.run(scan_cmd, capture_output=True, text=True)
        json_scan_data = json.loads(scan_result.stdout)

        profile = json_scan_data['profiles'][0]
        controls = profile['controls']

        controls_data = []

        i = 0
        for control in controls:

            i = i+1
            control_id = control.get('id')
            title = control.get('title')
            impact = control.get('impact', 0)
            tags = control.get('tags', [])


            results_list = []
            for result in control.get('results', []):
                entry = {
                    'status': result.get('status'),
                    'code_desc': result.get('code_desc'),
                    'message': result.get('message'),
                    'run_time': result.get('run_time')
                }
                results_list.append(entry)

            if any(r['status'] == 'failed' for r in results_list):
                overall_status = "failed"
            elif all(r['status'] == 'passed' for r in results_list):
                overall_status = "passed"
            else:
                overall_status = "skipped"


            control_entry = {
                'id': control_id,
                'title': title,
                'impact': impact,
                'tags': tags,
                'overall_status': overall_status,
                'results': results_list
            }
            controls_data.append(control_entry)


        print("How would you like to order scan results?")
        print("     1. Default order")
        print("     2. Failed First")
        choice = input("> ")

        if choice == "2" or choice.lower() in ["d", "default"]:
            ordered_controls = sort_controls_data(controls_data)
            print_scan_results(ordered_controls)  # Ordered by Failed > Passed > Skipped
        else:
            print_scan_results(controls_data) # In Natural/Standard order



def print_available_remediations(remediations_dict):
    print(f"Remediation         |        Description")

    for remediation in remediations_dict:
        func = remediation["function"]
        desc = remediation["description"]
        print(f"{func.__name__:16}    |        {desc:16}")

def print_controls():
    print("Only controls that failed can be remediated. There may be some controls for which a remediation hasn't yet been configured.")
    print("If there is a failed control that doesn't appear in this list, you can request it to be added by creating an Issue on the GitHub repository.")

def print_not_installed_message():
    print("InSpec is not installed or not working.")
    print("Please ensure InSpec is installed before continuing.")
    print("Exiting...")

def print_prompt():
    print(" What would you like to do?")
    print("     1. Scan your system")
    print("     2. Remediate a configuration")
    print("     3. Exit")

def print_scan_results(controls_data):
    init()  # initialize colorama

    num_passed_controls = 0
    num_failed_controls = 0
    num_skipped_controls = 0

    num_passed_tests = 0
    num_failed_tests = 0
    num_skipped_tests = 0

    for control in controls_data:

        status = control['overall_status']
        control_id = control['id']
        title = control['title']
        results = control['results']

        if status == "passed":
            color = Fore.LIGHTGREEN_EX
            symbol = "✔"
            num_passed_controls += 1
        elif status == "failed":
            color = Fore.LIGHTRED_EX
            symbol = "×"
            num_failed_controls += 1
        elif status == "skipped":
            color = Fore.YELLOW
            symbol = "-"
            num_skipped_controls += 1
        else:
            color = Fore.MAGENTA
            symbol = "?"

        print(color + symbol + " " + status.upper(), control_id, title)

        for result in results:
            result_status = result['status']
            description = result['code_desc']
            if result['message']:
                message = result['message']
            else:
                message = ""

            if result_status == "passed":
                color = Fore.LIGHTGREEN_EX
                symbol = "✔"
                num_passed_tests += 1
            elif result_status == "failed":
                color = Fore.LIGHTRED_EX
                symbol = "×"
                num_failed_tests += 1
            elif result_status == "skipped":
                color = Fore.YELLOW
                symbol = "-"
                num_skipped_tests += 1
            else:
                color = Fore.MAGENTA
                symbol = "?"

            print(color + "     " + symbol + " " + description)
            expected, got = parse_expected_got(message)

            if expected and got:
                print("        expected: ", expected)
                print("        got: ", got)

        print("")

    print(Fore.WHITE, "Controls: ", end="")
    print(Fore.LIGHTGREEN_EX, str(num_passed_controls) + " passed, ", end='')
    print(Fore.LIGHTRED_EX, str(num_failed_controls) + " failed, ", end='')
    print(Fore.WHITE, str(num_skipped_controls) + " skipped")

    print(Fore.WHITE, "Tests: ", end="")
    print(Fore.LIGHTGREEN_EX, str(num_passed_tests) + " passed, ", end='')
    print(Fore.LIGHTRED_EX, str(num_failed_tests) + " failed, ", end='')
    print(Fore.WHITE, str(num_skipped_tests) + " skipped")

def exit_from_prompt():
    print("Exiting...")
    sys.exit(1)



#TODO: Move below backend functions into a shared module, since they will likely also be used in the gui

# Finds the remediation METHOD/function in the Remedation.py file.
def find_remediation_function(function_name):
    func = getattr(remediations, function_name)
    return func

def get_available_remediations():
    # Parse the controls.json file
    # For each control in the controls.json file
        # Grab the remediation function_name
        # Check the remediations module to verify the function exists
            # Add to the list of remediations (Add the remediation function and description)
    # Print all valid remediation functions and descriptions from the list

    remediations_dict = []
    with open("config/controls.json") as controls_file:
        controls = json.load(controls_file)
        controls_data = controls["controls"]


        for control in controls_data:
            remediation_data = control["remediation"]
            func_name = remediation_data['function']

            function = find_remediation_function(func_name)

            if function:
                # Add function to the dictionary/list
                remediations_dict.append({
                    "function": function,
                    "description": remediation_data["description"]
                })
            else:
                print(
                    f"Control {control['id']} references "
                    f"missing remediation '{func_name}'"
                )

    return remediations_dict

def sort_controls_data(controls_data):
    print("Ordering controls data...")
    failed_controls = []
    passed_controls = []
    skipped_controls = []
    for control in controls_data:
        if control['overall_status'] == 'failed':
            failed_controls.append(control)
        elif control['overall_status'] == 'passed':
            passed_controls.append(control)
        else:
            skipped_controls.append(control)
    ordered_controls_data = failed_controls + passed_controls + skipped_controls
    return ordered_controls_data

def parse_expected_got(message: str):
    if not message:
        return None, None

    expected_match = re.search(r'expected:\s*"?([^"\n]+)"?', message)
    got_match = re.search(r'got:\s*"?([^"\n]+)"?', message)

    if expected_match and got_match:
        expected = expected_match.group(1) if expected_match else None
        got = got_match.group(1) if got_match else None
        return expected, got

    alt_message = re.search(r'expected\s+"([^"]+)"\s+to.*?"([^"]+)"', message)
    if alt_message:
        return alt_message.group(2), alt_message.group(1)

    return None, None