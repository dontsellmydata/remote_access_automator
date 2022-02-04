Purpose:

This script is designed to automate the process of giving access to devices in staging to a remote engineer.

Features:

* Create Active Directory user and add to the restricted VPN group.
* Create .txt file containing VPN connection details to send to the user.
* Enable ports on the ACI FEX switch linked to the customer staging bridge domain.

![alt text](https://github.com/dontsellmydata/remote_access_automator/blob/master/ads.gif "Adding AD user")

![alt text](https://github.com/dontsellmydata/remote_access_automator/blob/master/aci.gif "Enabling Ports in ACI")

![alt text](https://github.com/dontsellmydata/remote_access_automator/blob/master/template_demo_clean.jpg "Example email template")


Notes:

* If the staged devices have DHCP enable they will pick up an IP address in the 192.168.200.0/24 range
* The VPN user created will only have access to the 192.168.200.0/24 range.


Install instructions:

Windows:

* Check if python is installed
    * terminal: python -- version (needs to be 3.x)
    * if it isn’t installed download latest python and install it

* Navigate to the folder path in terminal containing staging_ra_automator.py
* pip3 install -r requirements.txt
* python3 staging_ra_automator.py

Mac/Linux:

* Check if python is installed
    * terminal: python3 —version
* Navigate to folder path in terminal containing staging_ra_automator.py
* pip3 install -r requirements.txt
* python3 staging_ra_automator.py
