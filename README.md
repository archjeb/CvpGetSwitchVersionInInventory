# CvpGetSwitchVersionInInventory.py 
Script to generate CSV report of all switches in CVP with a subset of show version content.

# Author
Jeremy Georges 

# Description
CvpGetSwitchVersionInInventory

The purpose of this script is to pull the inventory of all switchs from a  CVP server through the API.
Then request via eAPI to each switch the 'show version detail' output and create a CSV file that has the
switch hostname, model, serial number, EOS version and aboot version.

## CLI Arguments

```
usage: CvpGetSwitchVersionInInventory.py [-h] -s SERVER -u USERNAME
                                         [-p PASSWORD] -o OUTPUTFILE

Arguments for script

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        CVP Server IP/HOST
  -u USERNAME, --username USERNAME
                        CVP Username
  -p PASSWORD, --password PASSWORD
                        password
  -o OUTPUTFILE, --outputfile OUTPUTFILE
                        Name of CSV File
```
 


License
=======
BSD-3, See LICENSE file
