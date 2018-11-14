'''
SMS 5.X API Module

The purpose of this module is to enable easy access to the TippingPoint SMS API from python scripts

Author:        Howie Howerton
Create On:     Oct 26th, 2018
Last Modified: Oct 26th, 2018

TODO:
- extend backup_sms method to include other backup types (nfs, scp, sftp)

'''
import requests, urllib, re

class Client():
    '''A client object for interacting with the TippingPoint SMS API.'''

    def __init__(self, sms_api_key, sms_server, verify_certs=False):
        '''Initialize the client connection to SMS's API.'''
        self.sms_api_key = sms_api_key
        self.sms_server = sms_server
        self.verify_certs = verify_certs # This flag controls whether or not to ignore certificate warnings (ie: self-signed certs)

    
    def get_active_dv(self):
        '''Retrieves the active DV on the SMS'''
        url = "https://{sms_server}/ipsProfileMgmt/dvInfo?request=active".format(sms_server=self.sms_server)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        response = requests.get(url, headers=headers, verify=self.verify_certs)
        return response.text.strip()

    
    def get_all_dvs(self):
        '''Retrieves a list of all Digital Vaccines on SMS'''
        url = "https://{sms_server}/ipsProfileMgmt/dvInfo?request=all".format(sms_server=self.sms_server)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        response = requests.get(url, headers=headers, verify=self.verify_certs)
        dv_list = []
        for dv in response.text.split("\r\n"):
            if dv != '':
                dv_list.append(dv)
        return dv_list
        
    
    def upload_csv_ipv4(self, csv_path):
        '''method to upload IPv4-based reputation entries via CSV'''
        rep_type = "ipv4"
        params_dict = {'type': rep_type}
        params = urllib.urlencode(params_dict)         
        url = "https://{sms_server}/repEntries/import?{params}".format(sms_server=self.sms_server, params=params)
        print url       
        headers = {'X-SMS-API-KEY': self.sms_api_key}              
        files = {"file": open(csv_path, 'rb')}
        response = requests.post(url, headers=headers, files=files, params=params, verify=self.verify_certs)
        return response

    
    def upload_csv_domains(self, csv_path):
        '''method to upload domain-based reputation entries via CSV'''
        rep_type = "dns"
        params_dict = {'type': rep_type}
        params = urllib.urlencode(params_dict)
        url = "https://{sms_server}/repEntries/import?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}    
        files = {"file": open(csv_path, 'rb')}
        response = requests.post(url, headers=headers, files=files, params=params, verify=self.verify_certs)
        return response   


    def upload_csv_urls(self, csv_path):
        '''method to upload URL-based reputation entries via CSV'''
        rep_type = "url"
        params_dict = {'type': rep_type}
        params = urllib.urlencode(params_dict)
        url = "https://{sms_server}/repEntries/import?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}    
        files = {"file": open(csv_path, 'rb')}
        response = requests.post(url, headers=headers, files=files, params=params, verify=self.verify_certs)
        return response 

   
    def add_ip(self, ip, tag_string=''):
        '''method to add an ip address to reputation'''
        params_dict = {'ip': ip, 'TagData': tag_string}
        params = urllib.urlencode(params_dict)
        url = "https://{sms_server}/repEntries/add?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}    
        response = requests.post(url, headers=headers, params=params, verify=self.verify_certs)
        return response   

    
    def delete_ip(self, ip):
        '''method to delete an IP address entry from reputation'''
        #TODO: Need to insert logic to determine if an entry is an ip address or a domain.
        params_dict = {'ip': ip, 'criteria': "entry"}
        params = urllib.urlencode(params_dict)
        url = "https://{sms_server}/repEntries/delete?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}    
        response = requests.post(url, headers=headers, params=params, verify=self.verify_certs)
        return response  
    
    
    def ip_exists(self, ip):
        '''method to check if an ip-based reputation entry exists. 200=exists, 204=doesn't exist, 412=syntax error'''
        #TODO: Alter to handle multiple entries in one request
        params_dict = {'ip': ip}
        params = urllib.urlencode(params_dict)
        url = "https://{sms_server}/repEntries/query?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}    
        response = requests.post(url, headers=headers, params=params, verify=self.verify_certs)
        return response

 
    def add_domain(self, domain, tag_string):
        '''method to add a domain to reputation'''
        params_dict = {'dns': domain, 'TagData': tag_string}
        params = urllib.urlencode(params_dict)
        url = "https://{sms_server}/repEntries/add?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}    
        response = requests.post(url, headers=headers, params=params, verify=self.verify_certs)
        return response    

        
    def delete_domain(self, domain):
        '''method to delete a domain from reputation'''
        params_dict = {'dns': domain, 'criteria': "entry"}
        params = urllib.urlencode(params_dict)
        url = "https://{sms_server}/repEntries/delete?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}    
        response = requests.post(url, headers=headers, params=params, verify=self.verify_certs)
        return response           

       
    def domain_exists(self, domain):
        '''method to check if a domain exists within reputation. 200=exists, 204=doesn't exist, 412=syntax error'''
        #TODO: Alter to handle multiple entries in one request
        if not self.is_valid_domain(domain):
            return "Invalid Domain: {0}".format(domain)
        params_dict = {'dns': domain}
        params = urllib.urlencode(params_dict)
        url = "https://{sms_server}/repEntries/query?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}    
        response = requests.post(url, headers=headers, params=params, verify=self.verify_certs)
        return response          

 
    def add_url(self, url, tag_string):
        '''method to add a url to reputation'''
        #TODO: Add sanitization to check for 'http' or 'https' prefix.  If not there.. add it.
        if not self.is_valid_url(url):
            return "Invalid URL: {0}".format(url)
        params_dict = {'url': url, 'TagData': tag_string}
        params = urllib.urlencode(params_dict)
        url = "https://{sms_server}/repEntries/add?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}    
        response = requests.post(url, headers=headers, params=params, verify=self.verify_certs)
        return response    

        
    def delete_url(self, url):
        '''method to delete a url from reputation'''
        params_dict = {'url': url, 'criteria': "entry"}
        params = urllib.urlencode(params_dict)
        url = "https://{sms_server}/repEntries/delete?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}    
        response = requests.post(url, headers=headers, params=params, verify=self.verify_certs)
        return response           

       
    def url_exists(self, url):
        '''method to check if a url exists within reputation. 200=exists, 204=doesn't exist, 412=syntax error'''
        #TODO: Alter to handle multiple entries in one request
        if not self.is_valid_url(url):
            return "Invalid url: {0}".format(url)
        params_dict = {'url': url}
        params = urllib.urlencode(params_dict)
        url = "https://{sms_server}/repEntries/query?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}    
        response = requests.post(url, headers=headers, params=params, verify=self.verify_certs)
        return response  

    
    def delete_multiple_entries(self, list_of_entries_to_delete):
        '''method to delete multiple entries at once'''
        domains = []
        ips = []
        urls = []
        for item in list_of_entries_to_delete:
            if self.is_valid_domain(item):
                domains.append(item)
            if self.is_valid_ip(item):
                ips.append(item)
            if self.is_valid_url(item):
                urls.append(item)
        params_dict = {'criteria': 'entry'}
        if len(domains) > 0:
            params_dict['dns'] = domains
        if len(ips) > 0:
            params_dict['ip'] = ips
        if len(urls) > 0:
            params_dict['url'] = urls
        params = urllib.urlencode(params_dict, True)
        url = "https://{sms_server}/repEntries/delete?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}    
        response = requests.post(url, headers=headers, params=params, verify=self.verify_certs)
        return response                   

    
    def is_valid_ip(self, string):
        '''Check if a string is a valid IP address or not.'''
        is_valid = re.match("^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$", string)
        if is_valid:
            print "%s is a valid ip address" % string
            return True
        else:
            return False

    
    def is_valid_domain(self, string):
        '''Check if a string is a valid domain or not.'''
        is_valid = re.match("^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", string)
        if is_valid:
            print "%s is a valid domain" % string
            return True
        else:
            return False


    def is_valid_url(self, string):
        '''Check if a string is a valid URL or not.'''
        is_valid = re.match("^(https?|ftp)://[a-z0-9-]+(\.[a-z0-9-]+)+([/?].+)?$", string)
        if is_valid:
            print "%s is a valid URL" % string
            return True
        else:
            return False


    def get_virtual_segments(self):
        '''Retrieves a list of virtual segments'''
        url = "https://{sms_server}/virtualsegment/get".format(sms_server=self.sms_server)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        response = requests.get(url, headers=headers, verify=self.verify_certs)
        return response

    
    def get_sms_version(self):
        '''Retrieves the SMS version'''
        url = "https://{sms_server}/smsAdmin/info?request=version".format(sms_server=self.sms_server)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        response = requests.get(url, headers=headers, verify=self.verify_certs)
        return response.text.strip()  
        

    def backup_sms(self, backup_type='sms', location='', username='', password='', domain='', tos='0', dv='1', events='false', notify='true', timestamp='true', encryptionPass='null'):
        '''Backs up SMS configuration.  Note: It takes a few minutes for the backup to complete.  Once it does, the Backup Filename will be returned - ie: u'Backup filename: sms_102620180129.bak' '''
        params_dict = {}
        if backup_type == 'sms':
            print "SMS backup"
            params_dict = {'type': backup_type, 'tos': tos, 'dv': dv, 'events': events, 'notify': notify, 'timestamp': timestamp, 'encryptionPass': encryptionPass}
        elif backup_type == 'scp':
            print "SCP backup"
            if (username=='' or password=='' or location==''):
                return "Error!  When backing up to SCP, you must specify values for username, password and location parameters"
            else:
                params_dict = {'type': backup_type, 'tos': tos, 'dv': dv, 'events': events, 'notify': notify, 'timestamp': timestamp, 'encryptionPass': encryptionPass, 'username': username, 'password': password, 'location': location}
                #TODO:  Validate that 'location' is in the correct format
        elif backup_type == 'sftp':
            print "SFTP backup"
            if (username=='' or password=='' or location==''):
                return "Error!  When backing up to SFTP, you must specify values for username, password and location parameters"
            else:
                params_dict = {'type': backup_type, 'tos': tos, 'dv': dv, 'events': events, 'notify': notify, 'timestamp': timestamp, 'encryptionPass': encryptionPass, 'username': username, 'password': password, 'location': location}
                #TODO:  Validate that 'location' is in the correct format - sftp://<ip_or_hostname>/path/and/filename.bak 
        elif backup_type == 'smb':
            print "SMB backup"
            if (username=='' or password=='' or location=='' or domain==''):
                return "Error!  When backing up to SMB, you must specify values for username, password, domain and location parameters"
            else:
                if 1==1: #self.is_valid_domain(domain):
                    params_dict = {'type': backup_type, 'tos': tos, 'dv': dv, 'events': events, 'notify': notify, 'timestamp': timestamp, 'encryptionPass': encryptionPass, 'username': username, 'password': password, 'domain': domain, 'location': location}
                    #TODO:  Validate that 'location' is in the correct format  
        else:
            return "Error!  Unknown backup type: {backup_type}".format(backup_type=backup_type)
        params = urllib.urlencode(params_dict, True)
        url = "https://{sms_server}/smsAdmin/backup?{params}".format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        response = requests.get(url, headers=headers, verify=self.verify_certs)
        return response.text.strip()         


    def get_layer2_fallback_status(self, deviceName='', deviceGroupName=''):
        '''Returns Layer2 fallback status for a device or device group'''
        '''
        Sample return values:
            deviceName:      u'8400TX-d0000000=false'
            
            deviceGroupName: u'8400TX-d0000000=false,8400TX-d0000001=false'
        '''
        if not deviceName == '':
            params_dict = {'deviceName': deviceName}
        elif not deviceGroupName == '':
            params_dict = {'deviceGroupName': deviceGroupName}
        else:
            return "Error!  A deviceName or deviceGroupName must be specified."
        params = urllib.urlencode(params_dict)
        url = 'https://{sms_server}/deviceAdmin/getFallback?{params}'.format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        response = requests.get(url, headers=headers, verify=self.verify_certs)
        return response.text.strip()
    
    
    def set_layer2_fallback_status(self, L2FB, deviceName='', deviceGroupName=''):
        '''Sets the Layer2 fallback status for a device or device group'''
        #TODO:  Need to test on 'real' devices.  Ghost appliances do not seem to accept the commands.
        if (deviceName and L2FB):
            params_dict = {'deviceName': deviceName, 'L2FB': L2FB}
        elif ((not deviceGroupName == '') and L2FB):
            params_dict = {'deviceGroupName': deviceGroupName, 'L2FB': L2FB}
        else:
            return "Error!  A deviceName or deviceGroupName must be specified AND a value of 'true' or 'false' for L2FB must be specified."
        params = urllib.urlencode(params_dict)
        url = 'https://{sms_server}/deviceAdmin/setFallback?{params}'.format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        response = requests.get(url, headers=headers, verify=self.verify_certs)
        return response.text.strip()
    
    
    def import_vuln_scan(self, runtime, csv_path, vendor='SMS-Standard', product='Vulnscanner', version='1.0'):
        '''Use the import method to import a vulnerability scan file that is in native SMS-Standard format.'''
        #TODO:  Add sanity checking for parameters
        params_dict = {'vendor': vendor, 'product': product, 'version': version, 'runtime': runtime}
        params = urllib.urlencode(params_dict)
        url = 'https://{sms_server}/vulnscanner/import?{params}'.format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        files = {"file": open(csv_path, 'rb')}
        response = requests.post(url, headers=headers, files=files, verify=self.verify_certs)
        return response
    
    
    def convert_vuln_scan(self, runtime, csv_path, vendor, product, version):
        '''Use the convert method to convert a vulnerability scan file that is not in native SMS-Standard format to import to the SMS'''
        #TODO:  Add sanity checking for parameters
        if not vendor in ['Nexpose', 'Qualys-CSV', 'Nessus', 'Rapid7']:
            return "Error!  Vendor name not support: {vendor}".format(vendor)
        params_dict = {'vendor': vendor, 'product': product, 'version': version, 'runtime': runtime}
        params = urllib.urlencode(params_dict)
        url = 'https://{sms_server}/vulnscanner/convert?{params}'.format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        files = {"file": open(csv_path, 'rb')}
        response = requests.post(url, headers=headers, files=files, verify=self.verify_certs)
        return response
    
    
    def quarantine_ip(self, ip, policy='Default Response', timeout='60'):
        '''Use the quarantine method to quarantine an IP address.'''
        #Note: If a 400 reponse is received, go to Responder > Policies > Default Response.  In 'Initiation and Timeout', select the 'Allow an SNMP Trap or Web Service call to invoke this Policy'
        params_dict = {'ip': ip, 'policy': policy, 'timeout': timeout}
        params = urllib.urlencode(params_dict)
        url = 'https://{sms_server}/quarantine/quarantine?{params}'.format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        response = requests.get(url, headers=headers, verify=self.verify_certs)
        return response
    
    
    def unquarantine_ip(self, ip, policy='Default Response', timeout='60'):
        '''Use the unquarantine method to unquarantine an IP address.'''
        params_dict = {'ip': ip, 'policy': policy, 'timeout': timeout}
        params = urllib.urlencode(params_dict)
        url = 'https://{sms_server}/quarantine/unquarantine?{params}'.format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        response = requests.get(url, headers=headers, verify=self.verify_certs)
        return response
    
    
    def get_data_dictionary(self, format='sql', table=''):
        '''Retrieve the DataDictionary from the Database'''
        if not table == '':
            params_dict = {'method': 'DataDictionary', 'format': format, 'table': table}
        else:
            params_dict = {'method': 'DataDictionary', 'format': format}
        params = urllib.urlencode(params_dict)
        url = 'https://{sms_server}/dbAccess/tptDBServlet?{params}'.format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        response = requests.get(url, headers=headers, verify=self.verify_certs)
        return response 
    
    
    def get_data(self, begin_time, end_time, table, format='sql'):
        '''Use the GetData method to request data from specific tables and specify parameters and format.'''
        params_dict = {'method': 'GetData', 'begin_time': begin_time, 'end_time': end_time, 'table': table, 'format': format}
        params = urllib.urlencode(params_dict)
        url = 'https://{sms_server}/dbAccess/tptDBServlet?{params}'.format(sms_server=self.sms_server, params=params)
        print url
        headers = {'X-SMS-API-KEY': self.sms_api_key}
        response = requests.get(url, headers=headers, verify=self.verify_certs)
        return response         