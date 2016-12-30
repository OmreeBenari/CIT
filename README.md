# CIT - Cisco Investigation Toolkit

## About

CIT was built to allow an easier approach to initial forensics on Cisco Devices.
In order to investigate network devices, you, as a researcher will have to do alot of 
commandlining for examining every aspect.
The CIT tool Does all of it for you, all you need is an ip of the Device,
 Username, and Password.
The CIT tool connects to the Device, copies the OS binary, and a coredump file into the investigation directory, and preforms security and integrity checks on both of them automaticaly,
and exports all of the data into a readable doc file.
It does not try to lead the investigation from a to z (only from a to w), but rather to help the investigator through the initial plotting. 

Tested with IOS version 12.4 and 15.0.


## Documentation

Basic stracture of CIT is:

- **CIT.py**
- **Setup.py**
- **README.md**
- **Packages**
- **imports**
	- **Connector.py**
	- **Investigator.py**
	- **ReportHandler.py**
	- **Naft**


### Setup.py
'''
Responsible for installing the dependencies of the tool offline from the Packages directory.
installs the Paramiko module and its dependencies for connecting via SSH to network Devices.
'''

### CIT.py
'''
The main execution file. This class just manges the flow of the investigation process throughout. It imports the other classes of the tool and uses them.
'''

### Connector.py
'''
This Class manages the connecting to the device process.
'''

### Investigator.py
'''
This class manages the memory investigation process using the Naft tool with little adjustments. it's also using the Bin file to perform .text integrity check. it's extracting packets founded in the memory into a pcap file inside the investigation directory.
'''

### ReportHandler.py
'''
This class manages the reporting process. it gets data from the other classes and arranging it in a nice .doc file.
'''

### README.md 
'''
Just this readme file.
'''
