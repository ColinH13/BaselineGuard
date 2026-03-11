import sys

import shutil, subprocess
import json
from utils import *

def run():

    installed, version = check_inspec_installed()
    if not installed:
        print("InSpec is not installed or not working.")
        print("Please ensure InSpec is installed before continuing.")
        print("Exiting...")
        sys.exit(1)
    else:
        print("InSpec is installed with version ", version)

        print(" What would you like to do?")
        print("     1. Scan your system")
        print("     2. Remediate a misconfiguration")
        print("     3. Exit")

        choice = input("> ")
        if choice == "1" or choice == "scan":
            print("Starting scan...")
            with open("config/config.json") as config_file:
                config = json.load(config_file)
                profile = config["inspec_profile_linux"]
                subprocess.run(["inspec", "exec", profile, profile, f"--chef-license", "accept"], check=True)

        if choice == "2" or choice == "remediate":
            print("Starting remediation...")
        if choice == "3" or choice == "exit":
            print("Exiting...")
            sys.exit(1)

