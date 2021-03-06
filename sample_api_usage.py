'''
Ideas:
- SQLite DB to keep track of entries
- input sanitization and error reporting/feedback (ie: 
    - CSV must contain only ONE type of Reputation entry IP|Domain|URL
    - tag doesn't exist on SMS
    - validate tag_string is in the correct format for each rep type (ie: ',' vs '|')
- process HTTP responses (ie: 200, 400, 404, etc)
- Add sanitization to check for 'http' or 'https' prefix.  If not there.. add it.
- Add method to check to see if a URL is valid or not.
'''

from sms_5_api import Client
from datetime import datetime
import time, os, shutil

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
# Instantiate an instance of the sms_5_api Client 
client = Client(sms_api_key, sms_server, verify_certs=verify_certs)

def main():
    '''main routine'''
    for f in os.listdir(directory_to_watch):
        if str(f).lower().endswith(('.nessus')):
            full_path = os.path.join(directory_to_watch, f)
            print(full_path)
            runtime = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'  #"2014-01-20T13:01:15.255Z/2014-01-20T13:22:14.333Z"
            try:
                response = client.convert_vuln_scan(runtime, csv_path=full_path, vendor='Nessus', product='Nessus', version='7.2.2')
                print(response)
                shutil.move(full_path, os.path.join(directory_for_processed_scans, f))
                print("{f} has been successfully uploaded to SMS and has been moved to {dest_dir}".format(f=f, dest_dir=directory_for_processed_scans))
            except Exception, e:
                print("Error processing Nessus Scan.  The raw error message is:\n\n {e}".format(e=e))
    
if __name__ == '__main__':
    main()

'''
timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

response = client.get_active_dv()
response = client.get_all_dvs()
response = client.upload_csv_ipv4(r'C:\Users\Howie\code\sms_api\test_ipv4.csv')
response = client.upload_csv_domains(r'C:\Users\Howie\code\sms_api\test_domains.csv')
response = client.upload_csv_urls(r'C:\Users\Howie\code\sms_api\test_urls.csv')
response = client.add_ip('1.1.1.1', 'MalwareType,cncHost,MalwareSeverity,High,LastUpdated,2017-05-25,Reputation Entries TTL,2018-10-25 07:15:00-0400')
response = client.get_virtual_segments()
response = client.get_sms_version()
response = client.delete_ip('1.1.1.1')
response = client.ip_exists('1.1.1.1')
response = client.add_domain('foohowie.com', 'MalwareType,cncHost,MalwareSeverity,High,LastUpdated,2017-05-25,Reputation Entries TTL,2018-10-25 07:15:00-0400')
response = client.delete_domain('foohowie.com')
response = client.domain_exists('foohowie.com')
response = client.add_url('http://www.howierocks.com', 'MalwareType,cncHost,MalwareSeverity,High,LastUpdated,2017-05-25,Reputation Entries TTL,2018-10-25 07:15:00-0400')
response = client.delete_multiple_entries(['http://www.howierocks.com', '1.0.0.3', 'malwaredomain3.biz'])
response = client.backup_sms(backup_type='sms', location='', username='', password='', domain='', tos='0', dv='1', events='false', notify='true', timestamp='true', encryptionPass='null')
response = client.backup_sms(backup_type='sms', tos='0', dv='1', events='false', notify='true', timestamp='true', encryptionPass='null')
response = client.backup_sms(backup_type='scp', location='scp://scp.howielab.com/home/howie/sms_backups/{timestamp}sms.bak'.format(timestamp=timestamp), username='howie', password='blahfoo4', domain='', tos='0', dv='1', events='false', notify='true', timestamp='true', encryptionPass='null')
response = client.backup_sms(backup_type='smb', location='//server1.howielab.com/share/sms_backups/{timestamp}sms.bak'.format(timestamp=timestamp), username='howie', password='blahfoo4', domain='howielab', tos='0', dv='1', events='false', notify='true', timestamp='true', encryptionPass='null')
response = client.backup_sms(backup_type='sftp', location='sftp://sftp.howielab.com/home/howie/sms_backups/{timestamp}sms.bak'.format(timestamp=timestamp), username='howie', password='blahfoo4', domain='', tos='0', dv='1', events='false', notify='true', timestamp='true', encryptionPass='null')
response = client.get_layer2_fallback_status('8400TX-d0000000')
response = client.get_layer2_fallback_status(deviceGroupName='test')
response = client.set_layer2_fallback_status(L2FB='true', deviceGroupName='test')
'''
'''runtime = "2014-01-20T13:01:15.255Z/2014-01-20T13:22:14.333Z"
#runtime = "2016-09-11T00:00:00.003Z"
#response = client.import_vuln_scan(runtime, csv_path=r'C:\Users\Howie\code\sms_api\test_eVR_CSV_Native.csv', vendor='SMS-Standard', product='Vulnscanner', version='1.0')
response = client.convert_vuln_scan(runtime, csv_path=r'C:\Users\Howie\code\sms_api\eVR examples\1936.nessus', vendor='Nessus', product='Nessus', version='7.2.2')
print(response)'''
# TROUBLESHOOT:  u'Failed to import file. Reason: File is missing IP Address or CVE IDs.'
'''
response = client.quarantine_ip('1.1.1.1', policy='Default Response', timeout='60')
response = client.unquarantine_ip('1.1.1.1', policy='Default Response', timeout='60')
response = client.get_data_dictionary(table='ACTIONSET', format='xml')

r = client.get_data_dictionary(table='SIGNATURE', format='csv')
with open('dv.csv') as dv:
    dv.write(r.text)

response = client.get_data_dictionary(table='TDEVICE', format='csv')

begin_time = '1483246800'
end_time = epoch_time = str(int(time.time()))
r = client.get_data(begin_time, end_time, 'ALERTS', format='xml')
print r
'''


dt = datetime(2017, 1, 1)
def get_epoch_from_datetime(dt):
    '''Calculate epoch time from a datatime object'''
    epoch_format = str(int(time.mktime(dt.timetuple())))
    return epoch_format

epoch_dt = get_epoch_from_datetime(dt)


