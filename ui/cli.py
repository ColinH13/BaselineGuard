import sys

import shutil, subprocess
import json

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

        all_results = []
        for control in controls:
            control_id = control.get('id')
            title = control.get('title')
            impact = control.get('impact', 0)
            tags = control.get('tags', [])

            for result in control.get('results', []):
                entry = {
                    'id': control_id,
                    'title': title,
                    'impact': impact,
                    'tags': tags,
                    'status': result.get('status'),
                    'code_desc': result.get('code_desc'),
                    'message': result.get('message'),
                    'run_time': result.get('run_time')
                }
                all_results.append(entry)

            standard_order = all_results.copy()

            status_order = ['failed', 'passed', 'skipped']
            grouped_order = []
            for status in status_order:
                for result in all_results:
                    if result['status'] == status:
                        grouped_order.append(result)

            severity_order = sorted(
                all_results,
                key=lambda x: (-x['impact'], x['status'] != 'skipped') # puts skipped results last
            )

            sorted_results = {
                'standard': standard_order,
                'grouped': grouped_order,
                'severity': severity_order
            }


            standard_order_results = sorted_results['standard']

            for result in standard_order_results:
                print(result['status'] + ": " + result['title'])
                print("   ", result['impact'])
                print("   ", result['code_desc'])
                print("   ", result['message'])
                print("   ", result['run_time'])







def exit_from_prompt():
    print("Exiting...")
    sys.exit(1)

