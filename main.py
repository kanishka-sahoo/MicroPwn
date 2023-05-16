#!/usr/bin/env python3
import sys
import os
import socket
from banner import printbanner


def main():
    printbanner()

    # Show main details such as ip address, WiFi SSID, etc for user convenience
    def info_dump():
        curr_iface = os.popen(
            "route | awk '/Iface/{getline; print $8}'").read()
        current_addr = os.popen(
            "ip route get 1.2.3.4 | awk '{print $7}'").read()
        current_ssid = os.popen("iwgetid -r").read()

        print("    ❯ Current Interface:", curr_iface)
        print("    ❯ Current SSID:", current_ssid)
        print("    ❯ Current Interface:", current_addr)

    def clear():
        os.system("clear")

    # lists out some of the commands that can be used
    def commands():
        helpstr = '''\n\n Available Commands:
                \u001b[33;1mhelp - Displays this help page
                \u001b[33;1mscan - Scans the current network for all devices
                \u001b[33;1mtarget - Set target device
                \u001b[33;1mpscan - Send a flood of packets to the specified IP
                \u001b[33;1mtpg - Generate phishing page/portal for redirection
                \u001b[33;1mdname - Find out device name of IP (If it exists)
        '''

        print(helpstr)

    def scan():
        # get the host IP address
        addr = os.popen(
            "ip route show | grep -i -m1 'default via' | \
            awk '{print $3}'").read()
        addr = addr.replace("\n", "")

        # Use the host IP and run Nmap on the correspinding /24 block
        out = os.popen(
            "nmap " + addr + "/24 -n -sP | grep -i 'Nmap scan report' | \
            awk '{print $5}'").read()
        print("Devices detected: ")
        print(out)

    def dname():
        lookupip = input(
            "\n"" " "\u001b[34;1mEnter the IP address to lookup: ")
        try:
            # Gets the device name of the given IP address
            devname = socket.gethostbyaddr(lookupip)[0]
        except socket.herror:
            return "There eas an error."
        print(
            " " "\u001b[31;1mDevice name: ", end="")
        print(devname)

    def pscan():
        pscan_target = input(
            "\n"" " "\u001b[34;1mEnter the IP address to scan ports: ")

    def shell():
        cmdlist = {
            "help": commands,
            "exit": exit,
            "clear": clear,
            "scan": scan,
            "dname": dname
        }

        while (True):
            try:
                prompt = input(" " "\n" "\n"" \u001b[36;1mmpwn❯❯\u001b[0m ")
                cmdlist[prompt]()
            except Exception:
                print("\n" " " "\u001b[31;1mInvalid Command")
            except KeyboardInterrupt:
                print(
                    " " "\u001b[31;1mKeyboard Interrupt Detected, Exiting...")
                exit()
    info_dump()
    shell()


if __name__ == "__main__":
    main()
