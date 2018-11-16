'''
Overview:

This script is designed to check a directory for new .nessus scan files every X seconds.
If new .nessus scan files are discovered, they are uploaded to SMS via Web API.
Once a scan has been successfully uploaded, it will be moved to a separate "processed scans" directory.
This way, we ensure that only NEW .nessus scans are uploaded each time the script polls the "source" directory.


Installation Instructions:

Place this script (nessus_sms_evr.py) into the same directory as the SMS 5 API module (sms_5_api.py).
Be sure that python is installed (https://www.python.org/downloads/).  Note: This script has been tested on Widnows with python 2.7.
Install the only required, non-standard library module (requests) with this command:

    pip install requests

In the CONFIGURATION SECTION below, substitute the appropriate values for your environment.


Running the script:

From a command windows, type:  

    python .\nessus_server_evr.py 


Note:  If run as per the above, the script will run in the foreground  for as long as the command window is open.  
For longer-term usage, it may be best to run the script as a daemon OR alter the script (by removing the 'polling every X seconds' logic)
and execute the script via cron or Task Scheduler. 
'''

from sms_5_api import Client
from datetime import datetime
import time, os, shutil

################################### CONFIGURATION SECTION ###################################
'''
SMS API key that's used to authenticate.  You can retrieve this value from SMS by going to:
Admin > Authentication and Authorization > Users.  
Double click on the desired User account and copy the value of the API key.
'''
sms_api_key = '06B0CEE6-AE09-4829-BC21-0DA6780D7278'
# SMS's IP can be found in Admin > Server Properties > Network (tab)
sms_server = '192.168.19.50'
# Whether or not to enforce validation of certificates.  Set to False if using the default self-signed certificate on SMS.
verify_certs=False
# directory_to_watch is the directory into which we expect new .nessus scan files to be dropped
directory_to_watch = r'C:\Users\Howie\code\sms_api\eVR examples\inbox'
# The script will place .nessus scan files into the directory_for_processed_scans directory once they've been successfully processed.
directory_for_processed_scans = r'C:\Users\Howie\code\sms_api\eVR examples\processed'
# How often to check directory_to_watch for new .nessus files (given in seconds)
check_frequency_seconds = 60
##############################################################################################

def main():
    for f in os.listdir(directory_to_watch):
        if str(f).lower().endswith(('.nessus')):
            full_path = os.path.join(directory_to_watch, f)
            print("processing: {full_path}".format(full_path=full_path))
            runtime = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'  
            try:
                response = client.convert_vuln_scan(runtime, csv_path=full_path, vendor='Nessus', product='Nessus', version='7.2.2')
                print("Response from SMS: {response}".format(response=response))
                shutil.move(full_path, os.path.join(directory_for_processed_scans, f))
                print("{f} has been successfully uploaded to SMS and has been moved to {dest_dir}".format(f=f, dest_dir=directory_for_processed_scans))
            except Exception, e:
                print("Error processing Nessus Scan.  The raw error message is:\n\n {e}".format(e=e))
    
if __name__ == '__main__':
    # Instantiate an instance of sms_5_api.py's Client class.
    client = Client(sms_api_key, sms_server, verify_certs=verify_certs)
    # Start an infinite loop
    while True:
        runtime = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        print("{runtime} - Checking {directory} for new .nessus files\n".format(runtime=runtime, directory=directory_to_watch))
        main()
        print("Checking again in {check_frequency_seconds} seconds.\n".format(check_frequency_seconds=check_frequency_seconds))
        time.sleep(check_frequency_seconds)

