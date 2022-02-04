Purpose:

This script is designed to automate the process of giving access to devices in staging to a remote engineer.

Features:

* Create Active Directory user and add to the restricted VPN group.
* Create .txt file containing VPN connection details to send to the user.
* Enable ports on the ACI FEX switch linked to the customer staging bridge domain.

![alt text](https://github.com/dontsellmydata/remote_access_automator/blob/master/activedirectory.gif "Adding AD user")

![alt text](https://github.com/dontsellmydata/remote_access_automator/blob/master/aci.gif "Enabling Ports in ACI")

![alt text](https://github.com/dontsellmydata/remote_access_automator/blob/master/template_demo_clean.jpg "Example email template")


Install instructions:

* Navigate to folder path in terminal containing staging_ra_automator.py
* pip3 install -r requirements.txt
* python3 staging_ra_automator.py
