#!/usr/bin/env/python3
import pyfiglet
import sys
import re
import csv
import json
import ipaddress
import random
import time
import datetime
from colorama import init
from itertools import zip_longest
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
from prettytable import PrettyTable
from aci import *
from palo import *
from time import sleep
from passwordgenerator import pwgenerator
from ldap3 import Server, Connection, SUBTREE, NTLM, ALL
from ldap3.extend.microsoft.addMembersToGroups import (
    ad_add_members_to_groups as addUsersInGroups,
)

ad_server = ""
ad_username = ""
ad_password = ""

bad_ips = []

init(autoreset=True)


def prRed(skk):
    print(f"\033[91m {skk}\033[00m")


def prGreen(skk):
    print(f"\033[92m {skk}\033[00m")


def prYellow(skk):
    print(f"\033[93m {skk}\033[00m")


def get_data():
    company_name = []
    subnets = []
    ports = []
    first_name = []
    last_name = []
    try:
        with open("data.csv", mode="r") as csv_file:
            csv_reader = csv.DictReader(csv_file)

            for row in csv_reader:
                # get rid of blank entries
                if row["Company Name"] != "":
                    company_name.append(
                        row["Company Name"].replace(" ", "-").capitalize()
                    )
                if row["Default Gateway"] != "":
                    subnets.append(row["Default Gateway"])
                if row["Ports"] != "":
                    ports.append(row["Ports"])
                if row["First Name"] != "":
                    first_name.append(row["First Name"])
                if row["Last Name"] != "":
                    last_name.append(row["Last Name"])
    except:
        prRed("[-] Error reading data.csv file")
        sys.exit(1)
    # check if subnets are valid IPv4 subnets
    for subnet in subnets:
        try:
            if ipaddress.IPv4Interface(subnet).is_private:
                continue
            else:
                sys.exit(1)
        except:
            prRed(
                f"'[-] Subnet Error: {subnet}' isn't a valid private IPv4 subnet. Please enter valid private IPv4 subnets only. For example: 192.168.0.0/24"
            )
            sys.exit(1)

    # check if subnets overlap with the core lab addresses
    networks = []
    for ip in subnets:
        networks.append(ipaddress.IPv4Interface(ip).network)
    for subnet in networks:
        for bad_ip in bad_ips:
            if subnet.overlaps(ipaddress.IPv4Network(bad_ip)) == True:
                prRed(
                    f"[-] Subnet Error: Sorry, '{subnet}' overlaps with '{bad_ip}' which is already in use in the lab. Please choose another subnet."
                )
                sys.exit(1)

    # check if subnet gateway addresses have been inputted correctly
    networks = []
    for gateway in subnets:
        networks.append(ipaddress.IPv4Interface(gateway).network)

    for network in networks:
        for ip in subnets:
            if ip == str(network):
                prRed(
                    f"[-] Subnet Error: '{ip}' is a network address. Please enter default gateway address with slash mask... 10.200.0.254/24 for example."
                )
                sys.exit(1)

    # check if subnet already exists in an active staging group
    active_subnets = active_subnet_check()
    networks = []
    active_networks = []
    for ip in subnets:
        networks.append(ipaddress.IPv4Interface(ip).network)
    for ip in active_subnets:
        active_networks.append(ipaddress.IPv4Interface(ip).network)
    for subnet in networks:
        for active_ip in active_networks:
            if subnet.overlaps(ipaddress.IPv4Network(active_ip)) == True:
                prRed(
                    f"[-] Subnet Error: Sorry, '{subnet}' overlaps with '{active_ip}' which is active in existing staging (check option 1 on the script). Please choose another subnet."
                )
                sys.exit(1)

    # check if name fields are populated
    if not first_name or not last_name:
        prRed(
            "[-] First Name/Last Name Error: Please enter first and last names of the persons requiring access."
        )
        sys.exit(1)

    # check if first and last names are letters only
    for (x, y) in zip(first_name, last_name):
        if x.isalpha() != True or y.isalpha() != True:
            prRed(
                "[-] First Name/Last Name Error: Please only enter names with letters A-Z."
            )
            sys.exit(1)

    # make a dictionary of names from the two name lists using 'zip'
    names = dict(zip(first_name, last_name))

    # check if ports are in the correct range
    for port in ports:
        port = int(port)
        if port not in range(1, 49):
            prRed("[-] Port Error: Please only choose ports between 1 and 48.")
            sys.exit(1)

    return (company_name[0], subnets, ports, names)


def nl():
    print("\n")


def banner():
    font = "standard"
    ascii_banner = pyfiglet.figlet_format("Remote Access Automator v3.0", font=font)
    prYellow(ascii_banner)
    print("Created by George Grant - March 2022")
    print("-" * 80)


def create_password():
    password = pwgenerator.generate()

    return password


def menu():
    choice = input(
        """

1: Get active staging groups
2: Delete active staging groups
3: Create remote access to new staging using data in data.csv
0: Quit

>>> """
    )
    if choice == "1":
        get_groups()
        menu()
    if choice == "2":
        delete_staging()
        menu()
    if choice == "3":
        create_staging()
        menu()
    elif choice == "0":
        nl()
        signoff = [
            r"""
                        Goodbye...
                     .
                    / V\
                  / `  /
                 <<   |
                 /    |
               /      |
             /        |
           /    \  \ /
          (      ) | |
  ________|   _/_  | |
<__________\______)\__)

""",
            r"""Have a nice day!

()   ()      ()    /
  ()      ()  ()  /
   ______________/___
   \            /   /
    \^^^^^^^^^^/^^^/
     \     ___/   /
      \   (   )  /
       \  (___) /
        \ /    /
         \    /
          \  /
           \/
           ||
           ||
           ||
           ||
           ||
           /\
          /;;\
     ==============""",
            r"""Enjoy your tea...
            .------.____
         .-'       \ ___)
      .-'         \\\
   .-'        ___  \\)
.-'          /  (\  |)
         __  \  ( | |
        /  \  \__'| |
       /    \____).-'
     .'       /   |
    /     .  /    |
  .'     / \/     |
 /      /   \     |
       /    /    _|_
       \   /    /\ /\
        \ /    /__v__\
         '    |       |
              |     .#|
              |#.  .##|
              |#######|
              |#######|""",
            r"""That was fun wasn't it...
            
       /^-^\
      / o o \
     /   Y   \
     V \ v / V
       / - \
      /    |
(    /     |
 ===/___) ||

""",
            """How's your table tennis backhand coming along...?

          ,;;;!!!!!;;.
        :!!!!!!!!!!!!!!;
      :!!!!!!!!!!!!!!!!!;
     ;!!!!!!!!!!!!!!!!!!!;
    ;!!!!!!!!!!!!!!!!!!!!!
    ;!!!!!!!!!!!!!!!!!!!!'
    ;!!!!!!!!!!!!!!!!!!!'
     :!!!!!!!!!!!!!!!!'
      ,!!!!!!!!!!!!!''
   ,;!!!''''''''''
 .!!!!'
!!!!'
""",
        ]
        prYellow(random.choice(signoff))
        nl()
        sys.exit(0)
    else:
        nl()
        prRed(
            """
[-] You must only select 1, 2 or 3. Enter 0 to quit."""
        )
        sleep(1)
        nl()
        menu()


def connection():
    try:
        server = Server(
            ad_server,
            use_ssl=True,
            get_info=ALL,
            connect_timeout=2,
        )
        connect = Connection(
            server,
            user=f"LAB\{ad_username}",
            password=ad_password,
            authentication=NTLM,
            auto_referrals=False,
        )

        if not connect.bind():
            prRed(
                "[-][AD] Failed to connect to the AD Server. Are you connected to the lab SSID?"
            )
            sys.exit(1)
        return connect

    except:
        prRed(
            "[-][AD] Failed to connect to the AD Server. Are you connected to the lab SSID?"
        )
        sys.exit(1)


def get_groups():
    connected = connection()
    # get active groups
    active_groups = group_search(connected)
    apic_token = get_token()
    subnet_check = []

    if active_groups == 0:
        print("[+] No staging groups currently configured")
        sleep(1)
        return
    # do the following for every group in active groups list
    for group in active_groups:

        # get the bridge domain gateway(s)
        gateways = get_bd(apic_token, group.rsplit("-", 2)[0])

        # get any IP's and MAC addresses currently attached to the EPG
        endpoints = get_endpoints(group)

        t = PrettyTable(
            [
                "VPN User",
                "Computer",
                "Country",
                "Last Logon",
                "Subnets",
                "Endpoint IP",
                "Endpoint MAC",
                "FEX port",
            ]
        )

        search_base = "dc=lab,dc=lab"

        connected.search(
            search_base=search_base,
            search_filter=f"(&(objectClass=GROUP)(cn={group}))",
            search_scope=SUBTREE,
            attributes=["member"],
            size_limit=0,
        )
        # interate through the results
        for entry in connected.entries:
            # extracts usernames only
            regex_short = r" +CN=([a-zA-Z ]+)"
            # clean list of users
            username_list = re.findall(regex_short, str(entry))

            # get rid of the the first item in the list which we don't need
            username_list.pop(0)
            # convert distinguished names into sAMAccount names to search for VPN stats
            sAM_Account_Name_List = []
            for user in username_list:
                user = user.split()
                firstName = user[0]
                lastName = user[1]
                sAMAccount = firstName[0].lower() + lastName.lower()
                sAM_Account_Name_List.append(sAMAccount)

        # get VPN statistics
        vpn_data = get_last_logon(sAM_Account_Name_List)
        for (a, b, c, d, e, f, g, h) in zip_longest(
            username_list,
            vpn_data[2],
            vpn_data[1],
            vpn_data[0],
            gateways,
            endpoints[0],
            endpoints[1],
            endpoints[2],
            fillvalue="-",
        ):  # use zip_longest to iterate over multiple lists at the same time and place '-' if there is nothing.
            t.add_row(
                [a, b, c, d, e, f, g, h]
            )  # add the results as rows in the prettytable

        print(t.get_string(title=group))  # print the the table


def active_subnet_check():
    connected = connection()
    # get active groups
    active_groups = group_search(connected)
    apic_token = get_token()
    subnet_check = []

    if active_groups == 0:
        return active_groups
    # do the following for every group in active groups list
    for group in active_groups:
        # get the bridge domain gateway(s)
        gateways = get_bd(apic_token, group.rsplit("-", 2)[0])
        for subnet in gateways:
            subnet_check.append(subnet)

    return subnet_check


def active_user_check(connected, data):
    for name in data[3].items():

        # creating the new users distinguised name
        userdn = "cn={},cn=Users,dc=lab,dc=lab".format(
            name[0].capitalize() + " " + name[1].capitalize()
        )
        try:
            connected.search(
                userdn,
                "(objectClass=person)",
            )

            if connected.entries != []:
                sys.exit(1)
        except:
            prRed(
                f"[-][AD] Username Error: {name[0].capitalize() + ' ' + name[1].capitalize()} already exists in AD. Please choose another Firstname/Lastname combination."
            )


def create_users(connected, data):

    for name in data[3].items():
        user_password = create_password()

        # creating the new users distinguised name
        userdn = "cn={},cn=Users,dc=lab,dc=lab".format(
            name[0].capitalize() + " " + name[1].capitalize()
        )
        # creating the group distinguished name
        group_dn = f"cn={data[0] + '-Staging-Group'},cn=Users,dc=lab,dc=lab"

        # create account name using first and last name
        sAMAccountName = name[0][0].lower() + name[1].lower()

        try:
            connected.add(
                userdn,
                attributes={
                    "objectClass": ["organizationalPerson", "person", "top", "user"],
                    "sAMAccountName": sAMAccountName,
                    "userPrincipalName": sAMAccountName + "@lab.lab",
                    "displayName": name[0].capitalize() + " " + name[1].capitalize(),
                    "description": "Created by Staging-Automator",
                },
            )

            # set password
            connected.extend.microsoft.modify_password(userdn, user_password)
            # enable user (with password does not expire)
            connected.modify(
                userdn, {"userAccountControl": [("MODIFY_REPLACE", 65536)]}
            )

            # add user to Global Protect Customer Access group
            addUsersInGroups(connected, userdn, group_dn)

            print(
                f"[+][AD] User '{sAMAccountName}' created successfully and added to the '{data[0] + '-Staging-Group'}'."
            )

            # create template in local directory containing instructions for the user to connect
            create_template(name[0], name[1], user_password, data[1])

        except:
            prRed(
                f"[-][AD] Error creating user...{name[0].capitalize() + ' ' + name[1].capitalize()}"
            )


def create_group(connected, data):
    name = data[0]
    try:
        group_name = name.capitalize() + "-Staging-Group"
        group_dn = f"cn={group_name},cn=Users,dc=lab,dc=lab"
        object_class = "group"
        attr = {
            "cn": group_name,
            "description": "Created by Staging-Automator",
            "groupType": "-2147483646",
            "sAMAccountName": group_name,
        }
        connected.add(group_dn, object_class, attr)
        print(f"[+][AD] {group_name} created successfully.")
        create_users(connected, data)
    except:
        prRed(f"[-][AD] Error creating {group_name}.")
        sys.exit(1)


def delete_AD_group_members(connected, group_name):
    connected.search(
        search_base=f"cn={group_name},cn=Users,dc=lab,dc=lab",
        search_filter="(objectClass=group)",
        search_scope="SUBTREE",
        attributes=["member"],
    )
    start = "="
    end = ","
    for entry in connected.entries:
        for user in entry.member.values:
            try:
                connected.delete(user)
                print(
                    f"[+][AD] User '{user.split(start)[1].split(end)[0]}' deleted sucessfully."
                )
            except:
                prRed(
                    f"[-][AD] Error deleting user '{user.split(start)[1].split(end)[0]}'"
                )


def delete_AD_group(connected, group_name):
    try:
        connected.delete(f"cn={group_name},cn=Users,dc=lab,dc=lab")
        print(f"[+][AD] '{group_name}' deleted successfully.")
    except:
        prRed(f"[-][AD] Error trying to delete '{group_name}'")


def create_template(user_fname, user_lname, user_password, subnets):

    networks = []
    for gateway in subnets:
        network = ipaddress.IPv4Interface(gateway).network
        networks.append(str(network))

    user_sAM_account_name = user_fname[0].lower() + user_lname.lower()

    filename = user_sAM_account_name + "_email_template"

    template = {
        f"""
Hi {user_fname.capitalize()},
 
Your VPN Credentials are:

Username: {user_sAM_account_name}
Password: {user_password}
 
Please navigate to the GlobalProtect Portal at https://0.0.0.0

You will be prompted to login with your username and password to then download and install the correct version of the Palo Alto GlobalProtect VPN client for your OS.
 
Once you’ve done that you can then login with the portal address '0.0.0.0' and the same credentials.

It's a split tunnel VPN so only traffic destined for the below subnets will go through the tunnel.

{networks}

If you have any issues connecting please let me know.
 
Thanks,

     """
    }
    try:
        create_file = open(f"{filename}.txt", "w")
        create_file.writelines(template)
        create_file.close()
        return
    except:
        return


def group_search(connected):
    group_list = []
    # search AD looking for any groups with below description
    connected.search(
        "DC=lab,DC=lab",
        "(&(objectclass=group)(description=Created by Staging-Automator))",
    )
    # get the response as a json object
    response = json.loads(connected.response_to_json())
    if response["entries"] == []:
        return 0
    # save each entry in the list
    for entry in response["entries"]:
        # find where the name of the group starts in the string
        start = entry["dn"].find("CN=") + len("CN=")
        # find where it ends
        end = entry["dn"].find(",") + len(",") - 1
        # get everything between the start and end
        group_name = entry["dn"][start:end]
        # append it to the list
        group_list.append(group_name)
    # return the list of found groups
    return group_list


def create_DHCP_scope(name, gateways):
    # using the pypsrp and ip address modules to make this a lot easier!
    try:
        # create the WSMan object that it used to connected to the AD Server
        wsman = WSMan(ad_server, username=ad_username, password=ad_password, ssl=False)
        # Create the 'run space pool'
        with RunspacePool(wsman) as pool:
            # Create a scope for each address
            i = 1
            for gateway in gateways:
                network = ipaddress.IPv4Interface(gateway).network
                router = ipaddress.IPv4Interface(gateway)
                ps = PowerShell(pool)
                ps.add_script(
                    f"Add-DhcpServerV4Scope -name “{name.upper()}-SCOPE-{str(i)}” -StartRange {network[1]} -Endrange {network[-2]} -SubnetMask {network.netmask} -Description “created by staging-automator” -State Active"
                )
                ps.add_script(
                    f"Set-DhcpServerV4OptionValue -ScopeID {network[0]} -DNSServer 10.10.10.10 -Router {router.ip}"
                )
                ps.add_script(
                    f"Add-Dhcpserverv4ExclusionRange -ScopeId {network[0]} -StartRange {router.ip} -EndRange {router.ip}"
                )
                ps.invoke()
                if ps.had_errors == False:
                    print(
                        f"[+][AD] DHCP scope for {gateway} created and activated successfully."
                    )
                else:
                    print(f"[-][AD] Error trying to creating DHCP scope for {gateway}.")
                    print("ERROR:\n%s" % "\n".join([str(s) for s in ps.streams.error]))
                i += 1
    except:
        prRed("[-][AD] Error connecting to the AD server.")


def delete_DHCP_scope(gateways):
    # using the pypsrp and ip address modules to make this a lot easier!
    try:
        # create the WSMan object that it used to connected to the AD Server
        wsman = WSMan(ad_server, username=ad_username, password=ad_password, ssl=False)
        # Create the 'run space pool'
        with RunspacePool(wsman) as pool:
            # Create a scope for each address
            i = 1
            for gateway in gateways:
                network = ipaddress.IPv4Interface(gateway).network
                ps = PowerShell(pool)
                ps.add_script(f"Remove-DhcpServerv4Lease -ScopeId {network[0]}")
                ps.add_script(f"Remove-DhcpServerv4Scope -ScopeId {network[0]}")
                ps.invoke()
                if ps.had_errors == False:
                    print(f"[+][AD] DHCP scope {network[0]} deleted successfully.")
                else:
                    prRed(f"[-][AD] Error trying to delete DHCP scope {network[0]}.")
                    print("ERROR:\n%s" % "\n".join([str(s) for s in ps.streams.error]))
                i += 1

    except:
        prRed("[-][AD] Error connecting to the AD server.")


def create_staging():
    print("[+] Validating data.csv...")
    data = get_data()
    connected = connection()
    active_user_check(connected, data)
    print("[+] Data.csv looks good. Starting configuration...")
    start_time = time.perf_counter()
    aci(data)
    create_DHCP_scope(data[0], data[1])
    create_group(connected, data)
    palo(data)
    stop_time = time.perf_counter()
    duration = stop_time - start_time
    delta = str(datetime.timedelta(seconds=duration)).split(".")[0]
    pretty_timer = delta.split(":")
    print(f"[+] That took {pretty_timer[1]} minutes and {pretty_timer[2]} seconds.")
    nl()
    print(
        "[INFO] Check script directory for .txt file containing user VPN instructions."
    )


def delete_staging():
    # connect to AD
    connected = connection()
    # get the current active groups
    active_groups = group_search(connected)
    # store the groups in an itemised dictionary
    dict_of_groups = {i: active_groups[i] for i in range(0, len(active_groups))}
    if dict_of_groups == {}:
        print("[+] No staging groups currently configured")
        sleep(1)
        return

    t = PrettyTable(["Number", "Group"])
    for k, v in dict_of_groups.items():
        t.add_row([k, v])

    print(t)  # print the the table

    while True:
        try:
            choice = int(
                input(
                    """
Which group do you want to delete? (enter the group number or press enter to exit):
>>> """
                )
            )

            if choice in dict_of_groups.keys():
                answer = input(
                    f"""
Are you sure you want to delete '{dict_of_groups[choice]}' (y or n):
>>> """
                )

                if answer == "y":
                    print(
                        f"[+] Removing all configuration for '{dict_of_groups[choice]}'..."
                    )
                    start_time = time.perf_counter()
                    delete_AD_group_members(connected, dict_of_groups[choice])
                    delete_AD_group(connected, dict_of_groups[choice])
                    # get rid of 'staging-group' tag using rsplit
                    original_name = dict_of_groups[choice].rsplit("-", 2)
                    gateways = delete_aci(original_name[0])
                    delete_DHCP_scope(gateways)
                    delete_palo(original_name[0], gateways)
                    stop_time = time.perf_counter()
                    duration = stop_time - start_time
                    delta = str(datetime.timedelta(seconds=duration)).split(".")[0]
                    pretty_timer = delta.split(":")
                    print(
                        f"[+] That took {pretty_timer[1]} minutes and {pretty_timer[2]} seconds."
                    )
                    break

            else:
                prRed(
                    "[-] Please choose a number in the table that corresponds to a staging group."
                )

        except:
            prRed("[-] Please only choose numbers.")
            return


def main():
    banner()
    menu()


if __name__ == "__main__":
    main()
