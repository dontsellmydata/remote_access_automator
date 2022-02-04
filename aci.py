#!/usr/bin/env/python3
import requests
import json
import sys
import pwinput
from staging_ra_automator import nl
from time import sleep

APIC_ADDRESS = "192.168.104.10"


def get_ports():

    while True:

        try:
            port_list = []
            ports = [
                int(port)
                for port in input(
                    """
Please enter the FEX switch port numbers of where you have patched in devices:

>>> """
                ).split()
            ]

            for x in ports:
                if x in range(1, 49):
                    port_list.append(x)

                elif x == 0:
                    port_list = 0
                    sys.exit(1)

                else:
                    sys.exit(1)

            if port_list == []:
                sys.exit(1)
            else:
                return port_list

        except:

            if port_list == 0:
                nl()
                print("Goodbye...")
                nl()
                sys.exit(0)

            else:
                nl()
                print(
                    "[-] Please enter port numbers between 1 and 48 or enter 0 to quit."
                )


def get_APIC_password():
    password = pwinput.pwinput(
        prompt="""
        
Please enter the APIC admin password: 
    
>>> """,
        mask="*",
    )

    return password


def select_ports(token, ports):
    portList = ports

    uri = f"https://{APIC_ADDRESS}/api/node/mo/uni/tn-HighPoint-Customers/ap-Staging/epg-Customer-Access-EPG.json"

    payload = {
        "fvRsPathAtt": {
            "attributes": {
                "dn": "uni/tn-HighPoint-Customers/ap-Staging/epg-Customer-Access-EPG/rspathAtt-[topology/pod-1/paths-101/extpaths-101/pathep-[eth1/x]]",
                "encap": "vlan-2022",
                "mode": "native",
                "tDn": "topology/pod-1/paths-101/extpaths-101/pathep-[eth1/x]",
                "rn": "rspathAtt-[topology/pod-1/paths-101/extpaths-101/pathep-[eth1/x]]",
                "status": "created",
            },
            "children": [],
        }
    }

    dn = payload["fvRsPathAtt"]["attributes"]["dn"]
    rn = payload["fvRsPathAtt"]["attributes"]["rn"]
    tDn = payload["fvRsPathAtt"]["attributes"]["tDn"]

    for port in portList:
        new_dn = dn.replace("eth1/x", "eth1/{}").format(port)
        new_rn = rn.replace("eth1/x", "eth1/{}").format(port)
        new_tDn = tDn.replace("eth1/x", "eth1/{}").format(port)
        payload["fvRsPathAtt"]["attributes"]["dn"] = new_dn
        payload["fvRsPathAtt"]["attributes"]["rn"] = new_rn
        payload["fvRsPathAtt"]["attributes"]["tDn"] = new_tDn

        headers = {
            "Cookie": f"APIC-Cookie={token}",
        }

        session = requests.Session()

        requests.packages.urllib3.disable_warnings()
        response = session.post(
            uri, data=json.dumps(payload), headers=headers, verify=False
        ).json()

        if response["totalCount"] == "0":
            nl()
            print(f"[+] Port eth1/{str(port)} enabled successfully!")
        else:
            nl()
            print(f"[-] Error enabling port eth1/{str(port)}")
    nl()
    print("[+] Taking you back to the main menu...")
    sleep(3)


def get_token(apic_password):
    apic_user = "admin"
    apic_password = apic_password

    headers = {"content-type": "application/json", "cache-control": "no-cache"}

    uri = "https://{0}/api/aaaLogin.json".format(APIC_ADDRESS)

    payload = {"aaaUser": {"attributes": {"name": apic_user, "pwd": apic_password}}}

    session = requests.Session()

    requests.packages.urllib3.disable_warnings()
    response = session.post(
        uri, data=json.dumps(payload), headers=headers, verify=False
    ).json()

    try:
        key = list(response["imdata"][0]["aaaLogin"]["attributes"].keys())

        if key[0] == "token":

            token = response["imdata"][0]["aaaLogin"]["attributes"]["token"]
            return token

    except:
        nl()
        print("[-] Error: The APIC password is wrong.")
        return 0


def aci():
    # get list of ports the engineer has patched devices into on the FEX switch.
    ports = get_ports()
    # get the APIC admin password.
    APIC_password = get_APIC_password()
    # login to the APIC and get authenticated session cookie.
    token = get_token(APIC_password)
    while True:
        if token == 0:
            APIC_password = get_APIC_password()
            token = get_token(APIC_password)
        else:
            break
    # post the list of ports to the HPS Customer-Access-EPG.
    select_ports(token, ports)
