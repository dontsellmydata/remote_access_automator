#!/usr/bin/env/python3
import pyfiglet
import sys
from aci import *
from time import sleep
from password_strength import PasswordPolicy
from ldap3 import Server, Connection, NTLM, ALL
from ldap3.extend.microsoft.addMembersToGroups import (
    ad_add_members_to_groups as addUsersInGroups,
)


def password_checker(password):
    policy = PasswordPolicy.from_names(
        length=10,
        uppercase=1,
        numbers=1,
        special=1,
        nonletters=1,
    )
    tested_password = policy.test(password)

    return tested_password


def nl():
    print("\n")


def menu():
    banner()
    nl()
    choice = input(
        """
1: Create Active Directory user
2: Configure networking for staged devices
0: Quit

>>> """
    )
    if choice == "1":
        create_user()
        menu()
    elif choice == "2":
        aci()
        menu()
    elif choice == "0":
        print("Goodbye...")
        sys.exit(0)
    else:
        print("[-] You must only select either 1 or 2")
        sleep(2)
        nl()
        nl()
        menu()


def banner():
    ascii_banner = pyfiglet.figlet_format("HPS Remote Access Automator v1.0")
    print(ascii_banner)
    print("Created by George Grant 2022")
    print("-" * 80)


def get_args():

    firstname = input(
        """
The first name of the person requiring access:

>>> """
    )

    lastname = input(
        """
The last name of the person requiring access:

>>> """
    )

    while True:
        try:
            user_password = input(
                """
The new COMPLEX password for the person requiring access:

>>> """
            )

            checked_password = password_checker(user_password)

            if (
                checked_password == []
                and user_password.lower().find(firstname.lower()) == -1
                and user_password.lower().find(lastname.lower()) == -1
            ):

                adpass = input(
        """
Please enter the AD Server Administrator password:

>>> """
    )


                return adpass, firstname, lastname, user_password
            else:
                print(
                    """
[-] ERROR: Password must be:

[-] Longer than 10 characters
[-] Contain at least 1 uppercase character
[-] Contain at least 1 number
[-] Contain at least 1 special character
[-] NOT contain the users first or last name
            """
                )

        except:
            sys.exit("[-] ERROR: quitting...")

    


def connection(adpassword):
    # connect
    server = Server("10.52.219.205", use_ssl=True, get_info=ALL)
    connect = Connection(
        server,
        user="HPSLAB\Administrator",
        password=adpassword,
        authentication=NTLM,
        auto_referrals=False,
    )
    if not connect.bind():

        return 0
    nl()
    print("[+] Right, we're connected to the AD server! Let's create that user...\n")
    return connect


def create_user():
    
    args = get_args()

    try:
        connected = connection(args[0])
        if connected == 0:
            nl()
            print(
                "[-] Failed to connect to AD Server.\n[-] Check the password.\n[-] Are you connected to the HPSLAB Wireless or CATO VPN?"
            )
            nl()
            print("[-] Taking you back to the main menu...")
            sleep(3)
            return

    except:
        sys.exit("[-] ERROR: quitting...")

    # creating the new users distinguised name
    userdn = "cn={},cn=Users,dc=hps,dc=lab".format(
        args[1].capitalize() + " " + args[2].capitalize()
    )
    # location of the restricted Global Protect Palo VPN group
    customer_access_groupdn = "cn=GlobalProtect-Customer-Access,cn=Users,dc=hps,dc=lab"
    # create account name using first and last name
    sAMAccountName = args[1][0].lower() + args[2].lower()
    try:
        connected.add(
            userdn,
            attributes={
                "objectClass": ["organizationalPerson", "person", "top", "user"],
                "sAMAccountName": sAMAccountName,
                "userPrincipalName": sAMAccountName + "@hps.lab",
                "displayName": args[1].capitalize() + " " + args[2].capitalize(),
            },
        )
        # set password
        connected.extend.microsoft.modify_password(userdn, args[3])
        # enable user (with password does not expire)
        connected.modify(userdn, {"userAccountControl": [("MODIFY_REPLACE", 65536)]})
        # add user to Global Protect Customer Access group
        addUsersInGroups(connected, userdn, customer_access_groupdn)

        print(f"[+] BOOM! user: {sAMAccountName} created sucessfully!\n")

        choice = template_choice()

        if choice == 0:

            template = create_template(args[1], args[2], args[3])

            if template == 0:
                print(
                    """
[+] Template created successfully! Returning to menu..."""
                )
                sleep(2)
            else:
                print(
                    """
[-] Error making template...returning to menu."""
                )
                sleep(2)

        else:
            return

    except:
        print("[-] Error! Failed to create user :(")
        sys.exit(1)


def template_choice():

    choice = input(
        """
Would you like to create an email template containing details of the user you just created? Press any key to continue or 'N' to skip:

>>> """
    )
    if choice == "N":
        print(
            """
[+] Taking you back to the main menu..."""
        )
        return 1

    else:
        return 0


def create_template(user_fname, user_lname, user_password):

    user_sAM_account_name = user_fname[0].lower() + user_lname.lower()

    engineer_fname = input(
        """
Please enter your first name:

>>> """
    )

    filename = user_sAM_account_name + "_emailtemp"

    template = {
        f"""
Hi {user_fname.capitalize()},
 
Your VPN Credentials are:

{user_sAM_account_name} / {user_password}
 
Please navigate to the HighPoint Solutions GlobalProtect Portal at https://81.145.50.51

You will be prompted to login with your username and password to then download and install the correct version of the Palo Alto GlobalProtect VPN client for your OS.
 
Once you’ve done that you can then login with the same credentials.
 
It’s a split tunnel VPN so only traffic destined for 192.168.200.0/24 will go through the tunnel.
 
If you have any issues connecting please let me know.
 
Thanks,

{engineer_fname.capitalize()}

     """
    }
    try:
        create_file = open(f"{filename}.txt", "w")
        create_file.writelines(template)
        create_file.close()
        return 0
    except:
        return


def main():
    menu()


if __name__ == "__main__":
    main()
