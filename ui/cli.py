import sys

import shutil, subprocess
import json

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





        init() # initialize colorama
        for control in controls_data:

            status = control['overall_status']
            control_id = control['id']
            title = control['title']
            results = control['results']


            if status == "passed":
                color = Fore.LIGHTGREEN_EX
                symbol = "✔"
            elif status == "failed":
                color = Fore.LIGHTRED_EX
                symbol = "×"
            elif status == "skipped":
                color = Fore.YELLOW
                symbol = "-"
            else:
                color = Fore.MAGENTA
                symbol = "?"

            print(color + status.upper(), control_id, title)

            for result in results:
                result_status = result['status']
                description = result['code_desc']

                color = Fore.LIGHTGREEN_EX if result_status == "passed" else Fore.LIGHTRED_EX
                print(color + "        " + result_status + ": " + description)
        print("\n\n")







def exit_from_prompt():
    print("Exiting...")
    sys.exit(1)

