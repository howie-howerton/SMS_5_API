# sms_api

This is a python module to enable easy/quick development of python scripts that leverage the TippingPoint SMS Advanced Threat API.

Usage:

from sms_5_api import Client

sms_api_key = '06B0CEE6-AE09-4829-BC21-0DA6780D7278'

sms_server = '192.168.19.50'

ignore_certs=True

client = Client(sms_api_key, sms_server, verify_certs=False)

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
