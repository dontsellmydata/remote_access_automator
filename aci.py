#!/usr/bin/env/python3
import requests
import json
import sys
from main import nl, connection, group_search, prRed


APIC_ADDRESS = ""
APIC_PASSWORD = ""


def get_bd(token, name):
    headers = {
        "Cookie": f"APIC-Cookie={token}",
    }

    uri = f"https://{APIC_ADDRESS}/api/node/mo/uni/tn-lab-Customers/BD-{name}.json?query-target=children&target-subtree-class=fvSubnet"

    response = requests.get(uri, headers=headers, verify=False).json()

    ips = []
    for x in response["imdata"]:
        ips.append(x["fvSubnet"]["attributes"]["ip"])

    if ips:
        return ips
    else:
        prRed(f"[-][APIC] Error getting configured gateways for {name} BD.")


def get_endpoints(name):
    token = get_token()
    original_name = name.rsplit("-", 2)[0]
    headers = {
        "Cookie": f"APIC-Cookie={token}",
    }

    uri = f"https://{APIC_ADDRESS}/api/node/mo/uni/tn-lab-Customers/ap-Staging/epg-{original_name}.json?query-target=children&target-subtree-class=fvCEp&rsp-subtree=children&rsp-subtree-class=fvRsToVm,fvRsVm,fvRsHyper,fvRsCEpToPathEp"

    response = requests.get(uri, headers=headers, verify=False).json()

    ip = []
    mac = []
    port = []
    for x in response["imdata"]:
        ip.append(x["fvCEp"]["attributes"]["ip"])
        mac.append(x["fvCEp"]["attributes"]["mac"])
        attached_port = x["fvCEp"]["children"][0]["fvRsCEpToPathEp"]["attributes"][
            "tDn"
        ].rsplit("[", 1)
        port.append(attached_port[1][:-1])
    return ip, mac, port


def create_bd(token, name, gateways):
    headers = {
        "Cookie": f"APIC-Cookie={token}",
    }

    uri = (
        f"https://{APIC_ADDRESS}/api/node/mo/uni/tn-lab-Customers/BD-{name}.json"
    )

    payload = {
        "fvBD": {
            "attributes": {
                "dn": f"uni/tn-lab-Customers/BD-{name}",
                "mac": "00:22:BD:F8:19:FF",
                "arpFlood": "true",
                "name": name,
                "descr": "created by staging-automator",
                "rn": f"BD-{name}",
                "status": "created",
            },
            "children": [
                {
                    "dhcpLbl": {
                        "attributes": {
                            "dn": f"uni/tn-lab-Customers/BD-{name}/dhcplbl-Staging-DHCP",
                            "owner": "tenant",
                            "name": "Staging-DHCP",
                            "rn": "dhcplbl-Staging-DHCP",
                            "status": "created",
                        },
                        "children": [],
                    }
                },
                {
                    "fvRsCtx": {
                        "attributes": {
                            "tnFvCtxName": "Customer-Staging",
                            "status": "created,modified",
                        },
                        "children": [],
                    }
                },
                {
                    "fvRsBDToOut": {
                        "attributes": {
                            "tnL3extOutName": "GG-to-outside-Palo-L3Out",
                            "status": "created",
                        },
                        "children": [],
                    }
                },
            ],
        }
    }
    # for each gateway insert it into the payload at a certain index
    i = 1
    for ip in gateways:

        payload["fvBD"]["children"].insert(
            i,
            {
                "fvSubnet": {
                    "attributes": {
                        "dn": f"uni/tn-lab-Customers/BD-{name}/subnet-[{ip}]",
                        "ctrl": "",
                        "ip": ip,
                        "scope": "public",
                        "rn": f"subnet-[{ip}]",
                        "status": "created",
                    },
                    "children": [],
                }
            },
        )

    response = requests.post(
        uri, data=json.dumps(payload), headers=headers, verify=False
    ).json()

    if response["totalCount"] == "0":
        print(f"[+][APIC] {name} Bridge Domain created successfully.")
    else:
        prRed(f"[-][APIC] Error creating {name} Bridge Domain.")
        sys.exit(1)


def delete_bd(token, name):
    headers = {
        "Cookie": f"APIC-Cookie={token}",
    }

    uri = (
        f"https://{APIC_ADDRESS}/api/node/mo/uni/tn-lab-Customers/BD-{name}.json"
    )

    payload = {
        "fvBD": {
            "attributes": {
                "dn": f"uni/tn-lab-Customers/BD-{name}",
                "status": "deleted",
            },
            "children": [],
        }
    }

    response = requests.post(
        uri, data=json.dumps(payload), headers=headers, verify=False
    ).json()

    if response["totalCount"] == "0":
        print(f"[+][APIC] {name} Bridge Domain deleted successfully.")
    else:
        prRed(f"[-][APIC] Error deleting {name} Bridge Domain.")


def create_epg(token, name):

    headers = {
        "Cookie": f"APIC-Cookie={token}",
    }

    uri = f"https://{APIC_ADDRESS}/api/node/mo/uni/tn-lab-Customers/ap-Staging/epg-{name}.json"

    payload = {
        "fvAEPg": {
            "attributes": {
                "dn": f"uni/tn-lab-Customers/ap-Staging/epg-{name}",
                "prio": "level3",
                "name": name,
                "descr": "Created by staging-automator",
                "rn": f"epg-{name}",
                "status": "created",
            },
            "children": [
                {
                    "fvRsBd": {
                        "attributes": {
                            "tnFvBDName": name,
                            "status": "created,modified",
                        },
                        "children": [],
                    }
                }
            ],
        }
    }

    response = requests.post(
        uri, data=json.dumps(payload), headers=headers, verify=False
    ).json()

    if response["totalCount"] == "0":
        print(f"[+][APIC] {name} EPG created successfully.")
        add_contracts(token, name)
        add_pdom(token, name)
    else:
        prRed(f"[-][APIC] Error creating {name} EPG.")
        sys.exit(1)


def delete_epg(token, name):
    headers = {
        "Cookie": f"APIC-Cookie={token}",
    }

    uri = f"https://{APIC_ADDRESS}/api/node/mo/uni/tn-lab-Customers/ap-Staging/epg-{name}.json"

    payload = {
        "fvAEPg": {
            "attributes": {
                "dn": f"uni/tn-lab-Customers/ap-Staging/epg-{name}",
                "status": "deleted",
            },
            "children": [],
        }
    }
    response = requests.post(
        uri, data=json.dumps(payload), headers=headers, verify=False
    ).json()

    if response["totalCount"] == "0":
        print(f"[+][APIC] {name} EPG deleted successfully.")

    else:
        prRed(f"[-][APIC] Error deleting {name} EPG.")


def add_contracts(token, name):
    headers = {
        "Cookie": f"APIC-Cookie={token}",
    }

    uri = f"https://{APIC_ADDRESS}/api/node/mo/uni/tn-lab-Customers/ap-Staging/epg-{name}.json"

    payload = {
        "fvRsCons": {
            "attributes": {
                "tnVzBrCPName": "Allow-Everything",
                "status": "created,modified",
            },
            "children": [],
        }
    }
    response = requests.post(
        uri, data=json.dumps(payload), headers=headers, verify=False
    ).json()

    if response["totalCount"] == "0":
        print(f"[+][APIC] Contracts added to {name} EPG successfully.")
    else:
        prRed(f"[-][APIC] Error adding contracts to {name} EPG.")
        sys.exit(1)


def add_pdom(token, name):
    headers = {
        "Cookie": f"APIC-Cookie={token}",
    }

    uri = f"https://{APIC_ADDRESS}/api/node/mo/uni/tn-lab-Customers/ap-Staging/epg-{name}.json"

    payload = {
        "fvRsDomAtt": {
            "attributes": {
                "resImedcy": "immediate",
                "tDn": "uni/phys-GG-Staging-PDOM",
                "status": "created",
            },
            "children": [],
        }
    }
    response = requests.post(
        uri, data=json.dumps(payload), headers=headers, verify=False
    ).json()

    if response["totalCount"] == "0":
        print(
            f"[+][APIC] Physical Domain association added to {name} EPG successfully."
        )
    else:
        prRed(f"[-][APIC] Error adding Physical Domain association to {name} EPG.")
        sys.exit(1)


def select_ports(token, name, ports):
    connected = connection()
    groups = group_search(connected)
    vlan_encap = 2701
    if groups == 0:
        vlan_encap = 2701
    else:
        active_groups = len(groups)
        vlan_encap = vlan_encap + active_groups

    # replacing EPG name with variable
    uri = f"https://{APIC_ADDRESS}/api/node/mo/uni/tn-lab-Customers/ap-Staging/epg-{name}.json"
    # iterate port list and insert variables
    for port in ports:
        payload = {
            "fvRsPathAtt": {
                "attributes": {
                    "dn": f"uni/tn-lab-Customers/ap-Staging/epg-{name}/rspathAtt-[topology/pod-1/paths-101/extpaths-101/pathep-[eth1/{port}]]",
                    "encap": f"vlan-{str(vlan_encap)}",
                    "mode": "native",
                    "tDn": f"topology/pod-1/paths-101/extpaths-101/pathep-[eth1/{port}]",
                    "rn": f"rspathAtt-[topology/pod-1/paths-101/extpaths-101/pathep-[eth1/{port}]]",
                    "status": "created",
                },
                "children": [],
            }
        }

        headers = {
            "Cookie": f"APIC-Cookie={token}",
        }

        session = requests.Session()

        requests.packages.urllib3.disable_warnings()
        response = session.post(
            uri, data=json.dumps(payload), headers=headers, verify=False
        ).json()

        if response["totalCount"] == "0":
            print(f"[+][APIC] FEX Port eth1/{str(port)} enabled successfully.")
        else:
            prRed(f"[-][APIC] Error enabling port eth1/{str(port)}")


def create_FEX_interface_selector(token, name, ports):

    uri = f"https://{APIC_ADDRESS}/api/node/mo/uni/infra/fexprof-FEX101-Profile/hports-{name}-typ-range.json"
    # the initial payload
    payload = {
        "infraHPortS": {
            "attributes": {
                "dn": f"uni/infra/fexprof-FEX101-Profile/hports-{name}-typ-range",
                "name": name,
                "descr": "created by staging-automator",
                "rn": f"hports-{name}-typ-range",
                "status": "created,modified",
            },
            "children": [],
        }
    }
    # appending child entries to the intial payload depending on the number of ports requested.
    i = 2
    for port in ports:
        port_block = "block" + str(i)
        payload["infraHPortS"]["children"].append(
            {
                "infraPortBlk": {
                    "attributes": {
                        "dn": f"uni/infra/fexprof-FEX101-Profile/hports-{name}-typ-range/portblk-{port_block}",
                        "fromPort": port,
                        "toPort": port,
                        "name": port_block,
                        "rn": f"portblk-{port_block}",
                        "status": "created,modified",
                    },
                    "children": [],
                }
            }
        )
        i += 1
    # appending the policy group to complete the payload
    payload["infraHPortS"]["children"].append(
        {
            "infraRsAccBaseGrp": {
                "attributes": {
                    "tDn": "uni/infra/funcprof/accportgrp-GG-Staging-Policy-Group",
                    "status": "created,modified",
                },
                "children": [],
            }
        }
    )

    # sending the payload to the APIC
    headers = {
        "Cookie": f"APIC-Cookie={token}",
    }
    session = requests.Session()
    requests.packages.urllib3.disable_warnings()
    response = session.post(
        uri, data=json.dumps(payload), headers=headers, verify=False
    ).json()
    if response["totalCount"] == "0":
        print(f"[+][APIC] Interface Selectors created successfully.")
    else:
        prRed(
            f"[-][APIC] Error enabling Interface Selectors... are the ports you've chosen already in use?"
        )
        sys.exit(1)


def delete_FEX_interface_selector(token, name):
    headers = {
        "Cookie": f"APIC-Cookie={token}",
    }

    uri = f"https://{APIC_ADDRESS}/api/node/mo/uni/infra/fexprof-FEX101-Profile/hports-{name}-typ-range.json"

    payload = {
        "infraHPortS": {
            "attributes": {
                "dn": f"uni/infra/fexprof-FEX101-Profile/hports-{name}-typ-range",
                "status": "deleted",
            },
            "children": [],
        }
    }

    response = requests.post(
        uri, data=json.dumps(payload), headers=headers, verify=False
    ).json()

    if response["totalCount"] == "0":
        print(f"[+][APIC] {name} interface selectors deleted successfully.")

    else:
        prRed(f"[-][APIC] Error deleting {name} interface selectors.")


def get_token():
    apic_user = ""

    headers = {"content-type": "application/json", "cache-control": "no-cache"}

    uri = f"https://{APIC_ADDRESS}/api/aaaLogin.json"

    payload = {"aaaUser": {"attributes": {"name": apic_user, "pwd": APIC_PASSWORD}}}

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
        prRed("[-][APIC] Error: The APIC password is wrong.")
        sys.exit(1)


def delete_aci(name):
    token = get_token()
    gateways = get_bd(token, name)
    delete_bd(token, name)
    delete_epg(token, name)
    delete_FEX_interface_selector(token, name)
    return gateways


def aci(data):
    token = get_token()
    create_FEX_interface_selector(token, data[0], data[2])
    create_bd(token, data[0], data[1])
    create_epg(token, data[0])
    select_ports(token, data[0], data[2])
