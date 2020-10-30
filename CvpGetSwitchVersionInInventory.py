#!/usr/bin/env python
# 'CvpGetSwitchVersionInInventory'
# Basic Script to authenticate to Arista Cloudvision (CVP) and get all device version info and
# build a CSV with that data. Note, that we are just using the inventory from CVP and the
# username/password. Switches need to be accessible from the host you are running this script from

# Version 1.0
#

import requests
import json
import argparse
import getpass
import csv
import sys
import jsonrpclib
import ssl

# Requests items we need for our RESTApi queries
connect_timeout = 10
headers = {"Accept": "application/json",
           "Content-Type": "application/json"}
requests.packages.urllib3.disable_warnings()
session = requests.Session()

def build_arg_parser():
    parser = argparse.ArgumentParser(
        description='Arguments for script')
    parser.add_argument('-s', '--server',
                        required=True,
                        action='store',
                        help='CVP Server IP/HOST')
    parser.add_argument('-u', '--username',
                        required=True,
                        action='store',
                        help='CVP Username')
    parser.add_argument('-p', '--password',
                        required=False,
                        action='store',
                        help='password')
    parser.add_argument('-o', '--outputfile',
                        required=True,
                        action='store',
                        help='Name of CSV File')
    args = parser.parse_args()
    return args

def login(url_prefix, username, password):
    authdata = {"userId": username, "password": password}
    headers.pop('APP_SESSION_ID', None)
    response = session.post(url_prefix+'/web/login/authenticate.do', data=json.dumps(authdata),
                            headers=headers, timeout=connect_timeout,
                            verify=False)
    cookies = response.cookies
    try:
       headers['APP_SESSION_ID'] = response.json()['sessionId']
    except:
       # If we got here...it means authentication failed...
       print ("Authentication error to CVP server.")
       sys.exit(1)
    if response.json()['sessionId']:
        return response.json()['sessionId']

def logout(url_prefix):
    response = session.post('%s/web/login/logout.do' % url_prefix)
    return response.json()

def get_inventory(url_prefix):
    response = session.get('%s/cvpservice/inventory/devices' % url_prefix)
    if response.json():
        return response.json()

def main():
    args = build_arg_parser()
    #server username password are the args.
    # args.server
    # args.username

    #if no password is specified on the command line, prompt for it
    if not args.password:
        args.password = getpass.getpass(
            prompt='Enter password for host %s and user %s: ' %
                   (args.server, args.username))


    # Form our URL prefix for all communication to CVP server API requests
    cvpserver = 'https://%s' % args.server

    print ("****************************")
    print ("* Logging into CVP Server  *")
    print ("****************************")

    login(cvpserver, args.username, args.password)
    print ("****************************")
    print ("* Getting List of Devices  *")
    print ("****************************")

    allDevices = get_inventory(cvpserver)
    if allDevices is not None:
        # If we have something back from allDevices....then lets open our CSV file.
        with open(args.outputfile, 'w') as csvFile:
            writer = csv.writer(csvFile)
            #
            # Write header first
            # CSV Header
            header = ['SwitchName', 'Model', 'Serial Number', 'EOS Version', 'Aboot Version']
            writer.writerow(header)

            # Some SSL housekeeping...
            try:
                _create_unverified_https_context = ssl._create_unverified_context
            except AttributeError:
               # Legacy Python that doesn't verify HTTPS certificates by default
               pass
            else:
                # Handle target environment that doesn't support HTTPS verification
                ssl._create_default_https_context = _create_unverified_https_context

            for currentswitch in allDevices:
                # Management address to switch will be key 'ipAddress'
                # currentswitch['ipAddress'])
                try:
                    print ("Connecting to switch %s eAPI over https..." % str(currentswitch['fqdn']))

                    switch = jsonrpclib.Server( "https://%s:%s@%s/command-api" % (args.username,args.password,str(currentswitch['ipAddress'])))
                    output = switch.runCmds( 1,[ "show version detail"] )
                    row = []
                    row.append(str(currentswitch['fqdn']))
                    row.append(output[0]['modelName'])
                    row.append(output[0]['serialNumber'])
                    row.append(output[0]['version'])
                    # Aboot version here...
                    row.append(output[0]['details']['components'][0]['version'])
                    writer.writerow(row)
                except:
                    print ("Unable to connect to %s eAPI interface" % str(currentswitch['fqdn']))

        csvFile.close()

    logout(cvpserver)

    print ("*************")
    print ("* Complete  *")
    print ("*************")




if __name__ == "__main__":
    main()
