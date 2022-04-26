# Ldap3 Scripts
This collection of scripts is typically focused around using the ldap3 library for python3. 

# ulu.py (User Lookup)
Why? Because you're not always going to have Powershell/RSAT on your box.

## Installation of Project:
```
cd /opt
git clone whateverprojectURLis
cd ldap3scripts
python3 -m pip install -r requirements.txt
cp /opt/ldap3scripts/ulu.py /usr/local/bin/ulu
nano .env
# alter the contents of .env accordingly to your environment. 
# Note: Line 30 of ulu will require you to update with the domain short name.
```