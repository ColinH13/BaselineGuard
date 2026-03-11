import sys

import shutil, subprocess
import json



def check_inspec_installed():
    path = shutil.which("inspec")
    print(path)
    if path is None:
        return False, None
    try:
        version = subprocess.run(["inspec", "version"], capture_output=True, text=True, check=True)
        return True, version.stdout.strip()
    except subprocess.CalledProcessError:
        return False, None