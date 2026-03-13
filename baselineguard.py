import sys

import shutil, subprocess
import json

from ui import cli

def main():

    cli.run()

    #TODO: Once gui is implemented, run that by default. Only run cli when ran from terminal with a certain parameter


if __name__ == "__main__":
    main()