1. Connect the devices you want to enable for remote access to the lab FEX switch.
2. Edit 'data.csv' to include Company name, default gateway(s), ports and user(s).
3. Run the script (option 3 in the script menu).
4. Check your local directory for generated email template containing remote user logon instructions.
5. Check for remote user login statistics and discovered devices (option 1 in the script menu).
6. Delete script configuration after staging has been completed (option 2 in the script).

![](create.gif)


Script Install and run instructions:

Windows:

* Open terminal
* Install python3 by typing: python3 (download from windows app store)
* Once installed browse to the folder in terminal containing 'main.py' 'aci.py' 'palo.py' and 'requirements.txt'
* Upgrade pip:
    * pip3 install --upgrade pip
* Install the script requirements:
    * pip3 install -r requirements.txt
* Run the script:
    * python3 main.py

Mac/Linux:

* Open terminal
* Check if python3 is installed:
    * which python3
* If not installed, download and install from python.org
* Upgrade pip:
    * pip3 install --upgrade pip
* Install the script requirements:
    * pip3 install -r requirements.txt
* Run the script:
    * python3 main.py
