
import atexit
import getpass
import os
import subprocess

from six.moves import input

"""Utility (helper) methods for commandline functionality.
"""


def clear_screen_on_exit():
    """Registers an OS clear screen command on application exit."""
    def clear_screen():
        if platform.system() == "Windows":
            os.system("cls")
        else:
            os.system("clear")

    atexit.register(clear_screen)


def get_data():
    """Collects raw input and returns."""
    data = ""
    print("Please type data. Press ENTER twice or CTRL+C to end.")

    while data[-2:] != "\n\n":
        try:
            data += input()
            data += "\n"
        except KeyboardInterrupt:
            break

    return data.rstrip("\n")


def get_data_from_clipboard():
    """Returns what is in the clipboard."""
    process = subprocess.Popen(['pbpaste'], stdout=subprocess.PIPE, close_fds=True)
    stdout, stderr = process.communicate()
    return stdout.decode('utf-8')


def get_key():
    """Get and return key using getpass."""
    return getpass.getpass("Please enter key: ")


def store_data_in_clipboard(data):
    """Store data in clipboard."""
    process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
    stdoutdata, stderrdata = process.communicate(input=data.encode('utf-8'))


def wait_on_exit(message="Press ENTER key or CTRL+C to complete."):
    input(message)
