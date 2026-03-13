import sys

import shutil, subprocess
import json

from Tools.scripts.verify_ensurepip_wheels import print_error

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

        if choice == "2" or choice == "remediate":
            print("Starting remediation...")

        if choice == "3" or choice == "exit":
            exit_from_prompt()



def print_not_installed_message():
    print("InSpec is not installed or not working.")
    print("Please ensure InSpec is installed before continuing.")
    print("Exiting...")

def print_prompt():
    print(" What would you like to do?")
    print("     1. Scan your system")
    print("     2. Remediate a misconfiguration")
    print("     3. Exit")

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

        passed_tests = []
        failed_tests = []

        for control in controls:
            control_id = control.get("id")
            control_title = control.get("title")
            status = control.get('results')[0]['status']

            if status == "passed":
                passed_tests.append(control_title)
            elif status == "failed":
                failed_tests.append(control_title)
            else:
                print("Unknown status = ", status, file=sys.stderr)


        print("Passed tests: ", passed_tests)
        print("Failed tests: ", failed_tests)




def exit_from_prompt():
    print("Exiting...")
    sys.exit(1)

