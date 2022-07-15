#!/usr/bin/env/python3
import requests
import xmltodict
import json
import sys
import ipaddress
from time import sleep
from prettytable import PrettyTable


def prRed(skk):
    print(f"\033[91m {skk}\033[00m")


def prWhite(skk):
    print(f"\033[37m {skk}\033[00m")


def get_key():
    user = ""
    password = ""

    # disable ssl warning
    requests.packages.urllib3.disable_warnings()
    # get request, ignore self-signed cert warnings
    with requests.get(
        f"https://0.0.0.0/api/?type=keygen&user={user}&password={password}",
        verify=False,
    ) as response:
        # print status code (200=ok)
        # print(response.status_code)
        # store the xml response of the request as a string
        output = response.text
    # convert the xml string to a dictionary
    xml_dict = xmltodict.parse(output)
    # select the key variable
    key = xml_dict["response"]["result"]["key"]

    return key


def group_include_list(key, name):
    # Add the AD Group created to the User Identification -> Group Mapping -> Include list on the Palo.

    group_name = name.lower() + "-staging-group"
    group_dn = f"cn={group_name},cn=users,dc=lab,dc=lab"

    headers = {"X-PAN-KEY": key}
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/group-mapping/entry[@name='AD-VPN']/group-include-list"
    element = "&element="

    payload = f"<member>{group_dn}</member>"

    with requests.get(
        f"https://0.0.0.0/api/?type=config&action=set&xpath={xpath}{element}{payload}",
        verify=False,
        headers=headers,
    ) as response:
        output = response.text
        xml_dict = xmltodict.parse(output)
        if xml_dict["response"]["@status"] == "success":
            print("[+][Palo Alto] AD group mappings applied successfully.")
        else:
            prRed("[-][Palo Alto] Failed to apply AD group mappings.")
            sys.exit(1)


def get_last_logon(username_list):
    key = get_key()

    headers = {"X-PAN-KEY": key}
    last_logons = []
    country = []
    computer = []
    for user in username_list:
        with requests.get(
            f"https://0.0.0.0/api/?type=op&cmd=<show><global-protect-gateway><previous-user><user>{user}</user></previous-user></global-protect-gateway></show>",
            verify=False,
            headers=headers,
        ) as response:

            output = response.text
            xml_dict = xmltodict.parse(output)

            if xml_dict["response"]["result"] == None:
                last_logons.append("-")
                country.append("-")
                computer.append("-")
            elif type(xml_dict["response"]["result"]["entry"]) == type([]):
                last_logons.append(
                    (xml_dict["response"]["result"]["entry"][-1]["login-time"])
                )
                country.append(
                    (xml_dict["response"]["result"]["entry"][-1]["source-region"])
                )
                computer.append((xml_dict["response"]["result"]["entry"][-1]["client"]))

            else:
                last_logons.append(
                    (xml_dict["response"]["result"]["entry"]["login-time"])
                )
                country.append(
                    (xml_dict["response"]["result"]["entry"]["source-region"])
                )
                computer.append((xml_dict["response"]["result"]["entry"]["client"]))

    return last_logons, country, computer


def get_address_objects(key, name):

    # headers required with this request
    headers = {"X-PAN-KEY": key}
    # send the request and store the response as a string.
    with requests.get(
        f"https://0.0.0.0/restapi/v10.0/Objects/Addresses?location=vsys&vsys=vsys1",
        verify=False,
        headers=headers,
    ) as response:
        output = response.text

    # convert the string into a dictionary
    addresses = json.loads(output, strict=False)
    addresses_to_delete = []
    for i in addresses["result"]["entry"]:
        if "tag" in i:
            if i["tag"]["member"][0] == name:
                addresses_to_delete.append(i["@name"])
    return addresses_to_delete


def create_address_object(key, name, addresses):
    i = 1
    for address in addresses:
        instance_name = name + f"-address-{i}"
        # The headers required for this request
        headers = {"X-PAN-KEY": key, "@name": instance_name}
        # Body of the request
        body = {
            "entry": {
                "@name": instance_name,
                "ip-netmask": str(ipaddress.IPv4Interface(address).network),
                "tag": {"member": [name]},
                "description": name + " staging subnet",
            }
        }
        # send the request and store the response as a string.
        with requests.post(
            f"https://0.0.0.0/restapi/v10.0/Objects/Addresses?@name={instance_name}&location=vsys&vsys=vsys1",
            data=json.dumps(body),
            verify=False,
            headers=headers,
        ) as response:
            output = response.text

            if "success" in output:
                print(
                    f"[+][Palo Alto] Address object '{instance_name}'created successfully."
                )
            else:
                prRed(
                    f"[-][Palo Alto] Error creating '{instance_name}' address object."
                )
                sys.exit(1)
        i += 1


def create_tag(key, name):
    # The headers required for this request
    headers = {"X-PAN-KEY": key, "@name": name}
    # Body of the request
    body = {"entry": {"@name": name}}
    # send the request and store the response as a string.
    requests.post(
        f"https://0.0.0.0/restapi/v10.0/Objects/Tags?@name={name}&location=vsys&vsys=vsys1",
        data=json.dumps(body),
        verify=False,
        headers=headers,
    )


def get_address_groups(key):
    # headers required with this request
    headers = {"X-PAN-KEY": key}
    # send the request and store the response as a string.
    with requests.get(
        f"https://0.0.0.0/restapi/v10.0/Objects/AddressGroups?location=vsys&vsys=vsys1",
        verify=False,
        headers=headers,
    ) as response:
        output = response.text

    # convert the string into a dictionary
    groups = json.loads(output, strict=False)

    # search the groups dictionary to find only entries with desired tag.
    # list comprehension:
    tagged_groups = [
        i
        for i in groups["result"]["entry"]
        if "tag" in i
        if i["tag"]["member"][0] == "Staging"
    ]
    # create table instance
    t = PrettyTable(["Address Group Name", "Description", "Tag"])

    # go through the list and add entries to the table
    for i in tagged_groups:
        # Add keys and values to the table
        t.add_row([i["@name"], i["description"], i["tag"]["member"][0]])

    # print the table
    print(t)


def create_address_group(key, name):
    # The headers required for this request
    headers = {"X-PAN-KEY": key, "@name": name + "-Group"}
    # Body of the request
    body = {
        "entry": {
            "dynamic": {"filter": f"'{name}'"},
            "tag": {"member": ["Staging"]},
            "@name": name + "-Group",
            "description": "created by staging automator",
        }
    }
    # send the request and store the response as a string.
    with requests.post(
        f"https://0.0.0.0/restapi/v10.0/Objects/AddressGroups?@name={name}-Group&location=vsys&vsys=vsys1",
        data=json.dumps(body),
        verify=False,
        headers=headers,
    ) as response:
        output = response.text

        if "success" in output:
            print(f"[+][Palo Alto] Address group '{name}-Group' created successfully.")
        else:
            prRed(f"[-][Palo Alto] Error creating '{name}-Group' address group.")
            sys.exit(1)


def get_access_routes(key):
    # headers required with this request
    headers = {"X-PAN-KEY": key}
    # send the request and store the response as a string.
    with requests.get(
        f"https://0.0.0.0/restapi/v10.0/Network/GlobalProtectGateways?location=vsys&vsys=vsys1",
        verify=False,
        headers=headers,
    ) as response:
        output = response.text

    # convert the Global Protect Gateway config string into a dictionary
    config = json.loads(output, strict=False)

    return config


def print_access_routes(config):
    # create an instance of table specifying collumn names
    t = PrettyTable(["Split Tunnel Include Addresses"])
    # iterate through the dictionary to find the access routes
    for routes in config["result"]["entry"][0]["remote-user-tunnel-configs"]["entry"][
        0
    ]["split-tunneling"]["access-route"]["member"]:
        # Add values to the table
        t.add_row(
            [
                routes,
            ]
        )

    # print the table
    print(t)


def create_access_routes(key, addresses):
    # get the existing config from the FW
    config = get_access_routes(key)
    # headers required with this request
    headers = {
        "X-PAN-KEY": key,
    }

    for address in addresses:
        # append the new IP Addresses to the end of the access routes list
        config["result"]["entry"][0]["remote-user-tunnel-configs"]["entry"][0][
            "split-tunneling"
        ]["access-route"]["member"].append(
            str(ipaddress.IPv4Interface(address).network)
        )

    # remove the unwanted dictionary keys from the config so it's ready to post
    remove_keys = ["@total-count", "@count"]
    [config["result"].pop(key) for key in remove_keys]
    # chop off the preceeding keys
    config = config["result"]
    # save it as a json string
    body = json.dumps(config)

    # send the request and store the response as a string.
    with requests.put(
        "https://0.0.0.0/restapi/v10.0/Network/GlobalProtectGateways?@name=SSL-GATEWAY&location=vsys&vsys=vsys1",
        data=body,
        verify=False,
        headers=headers,
    ) as response:
        output = response.text

        if "success" in output:
            print(f"[+][Palo Alto] Subnets added to Split Tunnel successfully.")
        else:
            prRed(f"[-][Palo Alto] Error adding subnets to Split Tunnel.")
            sys.exit(1)


def create_security_rule(key, name):
    # The headers required for this request
    headers = {"X-PAN-KEY": key, "@name": name}
    group_name = name.lower() + "-staging-group"
    # Body of the request
    body = {
        "entry": {
            "@name": name,
            "from": {"member": ["SSL_VPN"]},
            "to": {"member": ["Staging-Zone"]},
            "source": {"member": ["any"]},
            "source-user": {"member": [f"cn={group_name},cn=users,dc=lab,dc=lab"]},
            "destination": {"member": name + "-Group"},
            "service": {"member": ["application-default"]},
            "application": {"member": ["any"]},
            "action": "allow",
        }
    }

    # send the request and store the response as a string.
    with requests.post(
        f"https://0.0.0.0/restapi/v10.0/Policies/SecurityRules?location=vsys&vsys=vsys1&@name={name}",
        data=json.dumps(body),
        verify=False,
        headers=headers,
    ) as response:
        output = response.text

        if "success" in output:
            print(f"[+][Palo Alto] Security Rule '{name}' created successfully.")
        else:
            prRed(f"[-][Palo Alto] Error creating '{name}' security rule.")
            sys.exit(1)

        move_security_rule(key, name)


def move_security_rule(key, name):
    # The headers required for this request
    headers = {
        "X-PAN-KEY": key,
        "@name": name,
        "where": "after",
        "dst": "Allow-Staging-to-AD",
    }

    requests.post(
        f"https://0.0.0.0/restapi/v10.0/Policies/SecurityRules:move?@name={name}&location=vsys&vsys=vsys1&where=after&dst=Allow-Staging-to-AD",
        verify=False,
        headers=headers,
    )


def delete_security_rule(key, name):
    headers = {"X-PAN-KEY": key, "@name": name}

    with requests.delete(
        f"https://0.0.0.0/restapi/v10.0/Policies/SecurityRules?@name={name}&location=vsys&vsys=vsys1",
        verify=False,
        headers=headers,
    ) as response:

        if "success" in response.text:
            print(f"[+][Palo Alto] Security Rule '{name}' deleted successfully.")
        else:
            prRed(f"[-][Palo Alto] Error deleting '{name}' security rule.")


def delete_address_objects(key, addresses):

    for address in addresses:
        headers = {"X-PAN-KEY": key, "@name": address}
        with requests.delete(
            f"https://0.0.0.0/restapi/v10.0/Objects/Addresses?@name={address}&location=vsys&vsys=vsys1",
            verify=False,
            headers=headers,
        ) as response:

            if "success" in response.text:
                print(
                    f"[+][Palo Alto] Address Object '{address}' deleted successfully."
                )
            else:
                prRed(f"[-][Palo Alto] Error deleting '{address}' Address Object.")


def delete_address_group(key, name):

    headers = {"X-PAN-KEY": key, "@name": name + "-Group"}

    with requests.delete(
        f"https://0.0.0.0/restapi/v10.0/Objects/AddressGroups?@name={name}-Group&location=vsys&vsys=vsys1",
        verify=False,
        headers=headers,
    ) as response:

        if "success" in response.text:
            print(f"[+][Palo Alto] Address group '{name}-Group' deleted successfully.")
        else:
            prRed(f"[-][Palo Alto] Error deleting '{name}-Group' address group.")


def delete_tag(key, name):
    # The headers required for this request
    headers = {"X-PAN-KEY": key, "@name": name}
    # Body of the request
    body = {"entry": {"@name": name}}
    # send the request and store the response as a string.
    with requests.delete(
        f"https://0.0.0.0/restapi/v10.0/Objects/Tags?@name={name}&location=vsys&vsys=vsys1",
        data=json.dumps(body),
        verify=False,
        headers=headers,
    ) as response:
        if "success" in response.text:
            print(f"[+][Palo Alto] Tag object for '{name}' deleted successfully.")
        else:
            prRed(f"[-][Palo Alto] Error deleting '{name}' Tag object.")


def delete_access_routes(key, addresses):
    # get the existing config from the FW
    config = get_access_routes(key)
    # headers required with this request
    headers = {
        "X-PAN-KEY": key,
    }

    for address in addresses:
        # remove IP Addresses from the end of the access routes list
        config["result"]["entry"][0]["remote-user-tunnel-configs"]["entry"][0][
            "split-tunneling"
        ]["access-route"]["member"].remove(
            str(ipaddress.IPv4Interface(address).network)
        )

    # remove the unwanted dictionary keys from the config so it's ready to post
    remove_keys = ["@total-count", "@count"]
    [config["result"].pop(key) for key in remove_keys]
    # chop off the preceeding keys
    config = config["result"]
    # save it as a json string
    body = json.dumps(config)
    # send the request and store the response as a string.
    with requests.put(
        "https://0.0.0.0/restapi/v10.0/Network/GlobalProtectGateways?@name=SSL-GATEWAY&location=vsys&vsys=vsys1",
        data=body,
        verify=False,
        headers=headers,
    ) as response:
        output = response.text

        if "success" in output:
            print(f"[+][Palo Alto] Addresses removed from Split Tunnel successfully.")
        else:
            prRed(f"[-][Palo Alto] Error adding removing addresses from Split Tunnel.")


def delete_group_include_list(key, name):
    # Add the AD Group created to the User Identification -> Group Mapping -> Include list on the Palo.

    group_name = name.lower() + "-staging-group"
    group_dn = f"cn={group_name},cn=users,dc=lab,dc=lab"

    headers = {"X-PAN-KEY": key}
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/group-mapping/entry[@name='AD-VPN']/group-include-list/member[text()="

    payload = f"'{group_dn}'"

    with requests.get(
        f"https://0.0.0.0/api/?type=config&action=delete&xpath={xpath}{payload}]",
        verify=False,
        headers=headers,
    ) as response:
        output = response.text
        xml_dict = xmltodict.parse(output)
        if xml_dict["response"]["@status"] == "success":
            print(
                f"[+][Palo Alto] AD group mappings for {group_name} deleted successfully."
            )
        else:
            prRed(
                f"[-][Palo Alto] Failed to delete AD group mappings for {group_name}."
            )


def commit_cat():
    cat = """
      |\      _,,,---,,_
ZZZzz /,`.-'`'    -.  ;-;;,_
     |,4-  ) )-,_. ,\ (  `'-'
    '---''(_/--'  `-'\_)
"""
    return cat


def commit(key):
    # The headers required for this request
    headers = {"X-PAN-KEY": key, "type": "commit", "cmd": "<commit></commit>"}
    # Body of the request

    # send the request and store the response as a string.
    with requests.post(
        f"https://0.0.0.0/api/?type=commit&cmd=<commit></commit>",
        verify=False,
        headers=headers,
    ) as response:
        output = response.text
        output_dict = xmltodict.parse(output)
        job = output_dict["response"]["result"]["job"]
        print(
            "[+][Palo Alto] Committing changes to the firewall. Go and make a tea... this will take a few minutes..."
        )
        prWhite(commit_cat())
        job_progress(key, job)


def job_progress(key, job):
    # The headers required for this request
    headers = {
        "X-PAN-KEY": key,
        "type": "op",
        "cmd": f"<show><jobs><id>{job}</id></jobs></show>",
    }

    # Check the progress of the job and if it's less than 100 keep checking
    progress = 0
    progress_dots = ""
    while progress < 100:
        with requests.post(
            f"https://0.0.0.0/api/?type=op&cmd=<show><jobs><id>{job}</id></jobs></show>",
            verify=False,
            headers=headers,
        ) as response:
            output = response.text
            output_dict = xmltodict.parse(output)
            progress = int(output_dict["response"]["result"]["job"]["progress"])
            print(f"{progress_dots}{progress}%", end="\r")
            progress_dots = progress_dots + "."
        sleep(3)
    # Finally check if the commit status for the job was sucessfull
    with requests.post(
        f"https://0.0.0.0/api/?type=op&cmd=<show><jobs><id>{job}</id></jobs></show>",
        verify=False,
        headers=headers,
    ) as response:
        output = response.text
        output_dict = xmltodict.parse(output)
        result = output_dict["response"]["result"]["job"]["details"]["line"]
        if result == "Configuration committed successfully":
            print("[+][Palo Alto] Commit was successfull.")
        else:
            prRed("[-][Palo Alto] Error whilst trying to commit changes.")


def delete_palo(name, gateways):
    key = get_key()
    addresses = get_address_objects(key, name)
    delete_security_rule(key, name)
    delete_address_objects(key, addresses)
    delete_address_group(key, name)
    delete_tag(key, name)
    delete_access_routes(key, gateways)
    delete_group_include_list(key, name)
    commit(key)


def palo(data):
    key = get_key()
    name = data[0]
    addresses = data[1]
    group_include_list(key, name)
    create_address_group(key, name)
    create_tag(key, name)
    create_address_object(key, name, addresses)
    create_access_routes(key, addresses)
    create_security_rule(key, name)
    commit(key)
