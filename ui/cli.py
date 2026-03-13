import sys

import shutil, subprocess
import json
from unittest import result

from colorama import Fore, Style, init

from utils import *

def run():

    installed, version = check_inspec_installed()
    if not installed:
        print_not_installed_message()
        sys.exit(1)
    else:
        print("InSpec is installed with version ", version)
        print_prompt()

        choice = input("> ")
        if choice == "1" or choice == "scan":
            run_scan()

        if choice == "3" or choice == "exit":
            exit_from_prompt()



def print_not_installed_message():
    print("InSpec is not installed or not working.")
    print("Please ensure InSpec is installed before continuing.")
    print("Exiting...")

def print_prompt():
    print(" What would you like to do?")
    print("     1. Scan your system")
    print("     3. Exit")

def run_scan():
    print("Starting scan...")
    with open("config/config.json") as config_file:
        print("check 1")
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
            print("check", i)
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

            print_scan_results(controls_data)



def exit_from_prompt():
    print("Exiting...")
    sys.exit(1)

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

            print(color + "        " + symbol + " " + result_status + ": " + description)
        print("\n")

    print("Controls: ", end="")
    print(Fore.LIGHTGREEN_EX, str(num_passed_controls) + " passed, ", end='')
    print(Fore.LIGHTRED_EX, str(num_failed_controls) + " failed, ", end='')
    print(str(num_skipped_controls) + " skipped, ")

    print("Tests: ", end="")
    print(Fore.LIGHTGREEN_EX, str(num_passed_tests) + " passed, ", end='')
    print(Fore.LIGHTRED_EX, str(num_failed_tests) + " failed, ", end='')
    print(str(num_skipped_tests) + " skipped, ")


