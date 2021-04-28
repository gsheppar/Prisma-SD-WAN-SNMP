# Prisma SD-WAN SNMP (Preview)
Script to help bulk create or delete SNMP Agent and SNMP traps. 

#### License
MIT

#### Requirements
* Active CloudGenix Account - Please generate your API token and add it to cloudgenix_settings.py
* Python >=3.6

#### Installation:
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run `SNMPAgent.py` or `SNMPTraps.py` scripts. 
 - pip install -r requirements.txt

### Examples of usage:
 Please generate your API token and add it to cloudgenix_settings.py
 
 - Get all current SNMP settings 
 1. ./SNMPAgent.py --get or ./SNMPTraps.py --get
 
 - Destroy all sites current SNMP settings if description matches your settings 
 1. Update SNMPAgent.py or SNMPTraps.py to have the right desction in the data 
 2. Here is an example data = {"description":"Example","tags":None,"v2_config":{"community":"test","enabled":"true"},"v3_config":None}
 3. Anything with SNMP description "Example" will be removed
 4. ./SNMPAgent --destroy or ./SNMPTraps.py --destroy
 
 - Destroy all sites current SNMP settings regardless of settings 
 1. ./SNMPAgent --destroyall or ./SNMPTraps.py --destroyall
 
 
 - Create all sites current SNMP settings 
 1. Update SNMPAgent.py or SNMPTraps.py to have the right settings in the data filed of data 
 2. Here is an example data = {"description":"Example","tags":None,"v2_config":{"community":"test","enabled":"true"},"v3_config":None}
 3. Will create this on all sites except for ones who already have SNMP description Example created. If you want to update settings then first delete and then re-create. 
 4. ./SNMPAgent or ./SNMPTraps.py


### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/cloudgenix-sd-wan.html>
