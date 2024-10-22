import shodan
import json

# API Key for Shodan
API_KEY = 'KEY'
api = shodan.Shodan(API_KEY)

# List of queries for different searches, without the vuln:* filter
# queries = {
#     "general_vulnerabilities": 'country:NL',
#     "windows_servers": 'os:"Windows Server 2012 R2" country:NL',
#     "domain_controllers": 'port:88,389,445 country:NL',
#     "smbv1_vulnerabilities": 'port:445 "SMBv1" country:NL',
#     "rdp_vulnerabilities": 'port:3389 country:NL',
#     "ics_critical_infrastructure": 'tag:ics country:NL',
#     "scada_critical_infrastructure": 'tag:scada country:NL',
#     "energy_sector_vulnerabilities": 'category:energy country:NL',
#     "modbus_vulnerabilities": 'port:502 country:NL',
#     "dnp3_vulnerabilities": 'port:20000 country:NL',
#     "cve_bluekeep": 'country:NL',  # We'll extract CVE details from vulns field
#     "exposed_mongodb": 'port:27017 country:NL',
#     "exposed_mysql": 'port:3306 country:NL',
#     "openvpn_vulnerabilities": 'port:1194 country:NL',
#     "pptp_vpn_vulnerabilities": 'port:1723 country:NL',
#     "broad_critical_infrastructure": 'tag:ics,scada,energy country:NL'
# }

# queries = {
#    "windows_xp_exposed_services": 'os:"Windows XP" port:445,3389,139 country:NL'

#     # Outdated SSL/TLS protocols
#     "outdated_ssl_tls": 'ssl.version:sslv3, tlsv1 country:NL',
    
#     # Exposed SSH servers with default configurations
#     "exposed_ssh_servers": 'port:22 country:NL',
    
#     # Exposed web servers running Apache/NGINX
#     "apache_nginx_web_servers": 'http.title:"Apache" OR http.title:"nginx" country:NL',
    
#     # Servers vulnerable to Heartbleed (CVE-2014-0160)
#     "heartbleed_vulnerabilities": 'vuln:CVE-2014-0160 country:NL',
    
#     # Exposed FTP servers on port 21
#     "exposed_ftp_servers": 'port:21 ftp country:NL',
    
#     # Systems vulnerable to EternalBlue (CVE-2017-0144)
#     "eternalblue_vulnerabilities": 'vuln:CVE-2017-0144 country:NL',
    
#     # Open SNMP (Simple Network Management Protocol) servers
#     "open_snmp_servers": 'port:161 country:NL',
    
#     # Unpatched Windows XP systems
#     "unpatched_windows_xp": 'os:"Windows XP" country:NL',
    
#     # Exposed Redis instances (port 6379)
#     "exposed_redis_servers": 'port:6379 redis country:NL',
    
#     # Vulnerable PHPMyAdmin installations
#     "vulnerable_phpmyadmin": 'http.html:"phpMyAdmin" vuln:* country:NL'
# }



### CVE Based queries

# queries = {
#     # EternalBlue (CVE-2017-0144)
#     "eternalblue_vulnerabilities": 'vuln:CVE-2017-0144 country:NL',
    
#     # Heartbleed (CVE-2014-0160)
#     "heartbleed_vulnerabilities": 'vuln:CVE-2014-0160 country:NL',
    
#     # Log4Shell (CVE-2021-44228)
#     "log4shell_vulnerabilities": 'vuln:CVE-2021-44228 country:NL',
    
#     # BlueKeep (CVE-2019-0708)
#     "bluekeep_vulnerabilities": 'vuln:CVE-2019-0708 country:NL',
    
#     # Shellshock (CVE-2014-6271)
#     "shellshock_vulnerabilities": 'vuln:CVE-2014-6271 country:NL',
    
#     # Apache Struts (CVE-2017-5638)
#     "apache_struts_vulnerabilities": 'vuln:CVE-2017-5638 country:NL',
    
#     # DROWN (CVE-2016-0800)
#     "drown_vulnerabilities": 'vuln:CVE-2016-0800 country:NL',
    
#     # Dirty COW (CVE-2016-5195)
#     "dirty_cow_vulnerabilities": 'vuln:CVE-2016-5195 country:NL',
    
#     # POODLE (CVE-2014-3566)
#     "poodle_vulnerabilities": 'vuln:CVE-2014-3566 country:NL',
    
#     # Spectre and Meltdown (CVE-2017-5753, CVE-2017-5715, CVE-2017-5754)
#     "spectre_meltdown_vulnerabilities": 'vuln:CVE-2017-5753 OR vuln:CVE-2017-5715 OR vuln:CVE-2017-5754 country:NL'
# }



### ICS/SCADA based queries
# queries = {
#     # Modbus devices
#     "modbus_devices": 'port:502 country:NL',
    
#     # DNP3 devices
#     "dnp3_devices": 'port:20000 country:NL',
    
#     # BACnet devices
#     "bacnet_devices": 'port:47808 country:NL',
    
#     # Siemens S7 devices
#     "siemens_s7_devices": 'port:102 country:NL',
    
#     # EtherNet/IP devices
#     "ethernet_ip_devices": 'port:44818 country:NL',
    
#     # PCWorx devices
#     "pcworx_devices": 'port:1962 country:NL',
    
#     # GE ICS devices
#     "ge_ics_devices": 'product:"General Electric" country:NL',
    
#     # Schneider Electric ICS devices
#     "schneider_electric_ics_devices": 'product:"Schneider Electric" country:NL',
    
#     # Siemens ICS devices
#     "siemens_ics_devices": 'product:"Siemens" country:NL',
    
#     # Rockwell Automation ICS devices
#     "rockwell_ics_devices": 'product:"Rockwell" country:NL',
    
#     # HMI web interfaces
#     "hmi_web_interface": 'http.title:"HMI" country:NL',
    
#     # SCADA web interfaces
#     "scada_web_interface": 'http.title:"SCADA" country:NL',
    
#     # PLC web interfaces
#     "plc_web_interface": 'http.title:"PLC" country:NL'
# }


# Function to perform Shodan search and save results
def search_and_save(api, query_name, query):
    try:
        # Execute the query
        results = api.search(query)
        output_data = []

        # Process the results
        for result in results['matches']:
            entry = {
                'IP': result['ip_str'],
                'Port': result['port'],
                'Vulnerabilities': result.get('vulns', 'None')  # Fetching vulns from the result details
            }
            output_data.append(entry)

        # Save the results to a JSON file
        with open(f'ics-scada/{query_name}_results.json', 'w') as f:
            json.dump(output_data, f, indent=4)

        print(f"Results for {query_name} saved in {query_name}_results.json")

    except shodan.APIError as e:
        print(f"Error with query '{query_name}': {str(e)}")

# Loop through each query and execute
for query_name, query in queries.items():
    search_and_save(api, query_name, query)
