import subprocess
import pprint
from zapv2 import ZAPv2
import requests
import sys
import time
import os
import optparse

'''
Passive Scan is checking theses issues:

    Application Error Disclosure	Medium	Release
    Content-Type Header Missing	Medium	Release
    Cookie No HttpOnly Flag	Medium	Release
    Cookie Without Secure Flag	Medium	Release
    Cross-Domain JavaScript Source File Inclusion	Medium	Release
    Incomplete or No Cache-control and Pragma HTTP Header Set	Medium	Release
    Private IP Disclosure	Medium	Release
    Script Passive Scan Rules	Medium	Release
    Secure Pages Include Mixed Content	Medium	Release
    Session ID in URL Rewrite	Medium	Release
    Stats Passive Scan Rule	Medium	Release
    Web Browser XSS Protection Not Enabled	Medium	Release
    X-Content-Type-Options Header Missing	Medium	Release
    X-Frame-Options Header Scanner	Medium	Release


Active Scan:

Client Browser		
Information Gathering	Default	Default
    Directory Browsing	Default	Default	Release
Injection	Default	Default
Buffer Overflow	Default	Default	Release
    CRLF Injection	Default	Default	Release
    Cross Site Scripting (Persistent)	Default	Default	Release
    Cross Site Scripting (Persistent) - Prime	Default	Default	Release
    Cross Site Scripting (Persistent) - Spider	Default	Default	Release
    Cross Site Scripting (Reflected)	Default	Default	Release
    Format String Error	Default	Default	Release
    Parameter Tampering	Default	Default	Release
    Remote OS Command Injection	Default	Default	Release
    Server Side Code Injection	Default	Default	Release
    Server Side Include	Default	Default	Release
    SQL Injection	Default	Default	Release
Miscellaneous	Default	Default
    External Redirect	Default	Default	Release
    Script Active Scan Rules	Default	Default	Release
Server Security	Default	Default
    Path Traversal	Default	Default	Release
    Remote File Inclusion	Default	Default	Release
'''

def setRuleForBasicAuthentication(zap):

    # Configure replacer to add basic authentication for all HTTP requests.
    rules = zap.replacer.rules
    for rule in rules:
        if rule[u'description'] == u'ADD_HTTP_BASIC_AUTHENTICATION_FOR_ALL_REQUESTS':
            found = True
            break
    if found == False:
        status = requests.get(
        url="http://localhost:8080/JSON/replacer/action/addRule/?zapapiformat=JSON&apikey=ko64mqb7iign34o0uiacon0unb&formMethod=GET&description=ADD_HTTP_BASIC_AUTHENTICATION_FOR_ALL_REQUESTS&enabled=true&matchType=REQ_HEADER&matchRegex=false&matchString=Authorization&replacement=Basic+YWRtaW46MTIzNDU2&initiators=")
        print ('Rule Was added\n ')
    else:
        print ("Rule is already exist...\n")

def addScanPolicy(zap, scan_policy):
    # Add Scan Policy
    policy_path = scan_policy
    zap.ascan.import_scan_policy(path=policy_path)
    #TODO - split by '/' to set policy below not hard coded
    zap.ascan.set_enabled_policies('injection_remote_host_command_injection.policy')

    #zap.ascan.import_scan_policy(path='/zap/injection_remote_host_command_injection.policy')
    #zap.ascan.set_enabled_policies('injection_remote_host_command_injection.policy')

    # Set Specific Policy file according to user choice and exlude defualt policy.
    exist_policy_list = zap.ascan.scan_policy_names

    while len(exist_policy_list) > 1:
        policy_name = exist_policy_list.pop(-1)
        zap.ascan.remove_scan_policy(scanpolicyname=policy_name)

    # verifying all scan policies were deleted. (first scan policy still exist )
    exist_policy_list = zap.ascan.scan_policy_names
    if (len(exist_policy_list) != 1) :
        print("Policy list includes more than one scan policy file..\n")
        sys.exit(1)
    print ("Scan Policy was Added!\n")


def authenticate_site(url):
    username = 'admin'
    password = '123456'
    lurl = url
    try:
        r = requests.get(url=lurl, auth=(username, password))
    except Exception as e:
        print("Couldn't run basic authentication for  " + str(lurl) + '\n' + str(e))
        exit(0)

    if str(r.status_code) == '200':
        print("Authentication completed successfully!\n")
    else:
        print("Couldn't not authenticate with UFM server...\n exiting...\n")
        sys.exit(0)


def runAjaxSpider(zap, target):
    # Trying to use AJAX spider
    timeout = 0

    zap.ajaxSpider.set_option_max_crawl_depth(integer=3)
    zap.ajaxSpider.set_option_max_duration(integer=30)

    res = zap.ajaxSpider.scan(url=target,)
    u_status = zap.ajaxSpider.status
    while u_status.encode('utf-8') == 'running':
        print ("Spider progress is :" + u_status.encode('utf-8'))
        time.sleep(5)
        u_status = zap.ajaxSpider.status
        timeout += 1
        if timeout == 36:
            print ("Spider stopped ! more than 3 minutes...")
            return
    print("Spider completed!\n")

    # Printing the results of the Ajax Spider:
    spider_number_of_results = zap.ajaxSpider.number_of_results
    spider_res = zap.ajaxSpider.full_results


def runActiveScan(zap, target):
    # Scan specefic test case using active scanner:
    scan_id = zap.ascan.scan(url=target)
    alert_id_list = zap.ascan.alerts_ids(scanid=scan_id)
    # Get all Alert ID's for specific scan
    if alert_id_list != u'Does Not Exist':
        alert_id_list = zap.ascan.alerts_ids(scanid=scan_id)
        for alert in alert_id_list:
            alert_info = zap.core.alert(id=alert)
    else:
        print ("[+]No Alert were found!\n")


def startDeamon(zap):
    # start Proxy server on port 8090 ( using subprocess )
    command = '/opt/zaproxy/zap.sh -daemon'
    try:

        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except Exception as e:
        print("Couldn't start proxy server on port 8080" + str(e))
        exit(1)


def shutOffDeamon(zap):
    zap.core.shutdown()
    print ("Proxy is disabled")

def main():

    #Parsing paramters:
    parser = optparse.OptionParser(usage="")
    parser.add_option('-p', dest='policy_file', defualt='default_policy', description='scan policy file from list')
    parser.add_option('-c',dest='content', description='Content file path including pre defined Authentication/Users/Url Content')

    (options, args) = parser.parse_args()

    if options.content is None :
        print ("Content file was not given..\nplease follow script usage rules\n")
        parser.print_usage()
        sys.exit(0)



    target = 'http://10.209.27.129/ufm_web/#/login'
    apikey = 'ko64mqb7iign34o0uiacon0unb'

    # TODO - check Authentication:
    # UFM are using GET request with Basic Authentication.
    known_urls_list = ['http://10.209.27.129/ufm_web/', 'http://10.209.27.129/ufm_web/#/ufm/dashboard','http://10.209.27.129/ufm_web/#/ufm/inventory',\
                       'http://10.209.27.129/ufm_web/#/ufm/ports','http://10.209.27.129/ufm_web/#/ufm/ports','http://10.209.27.129/ufm_web/#/ufm/ports', \
                       'http://10.209.27.129/ufm_web/#/ufm/system-health/ufm-health', 'http://10.209.27.129/ufm_web/#/login']

    ufm_authentication_url = 'http://10.209.27.129/ufmRest/app/users'
    #authenticate_site(ufm_authentication_url)


    # By default ZAP API client will connect to port 8080
    zap = ZAPv2(apikey=apikey)

    # start Proxy server with Owasp API:
    startDeamon(zap)

    #TODO- Import content for ZAP
    zap.context.import_context(contextfile='/zap/ufm_content.context')
    content_name = zap.context.context_list
    zap.context.set_context_in_scope(contextname=content_name, booleaninscope=1)


    #Create an empty session with target site
    zap.httpsessions.create_empty_session(site='http://10.209.27.129/ufm_web/')


    # Add scan policy
    addScanPolicy(zap , policy_file)

    #Add Rules for HTTP requests with basic autentication
    setRuleForBasicAuthentication(zap)

    # Trying to shutoff the passive scanner (it is run automatically after starting the proxy)
    # TODO - IS IT NECESSARY?
    records_to_scan = zap.pscan.records_to_scan
    zap.pscan.disable_all_scanners(apikey=apikey)

    # Set access for specific URL to be able to run asan.
    for url in known_urls_list:
        zap.core.access_url(url=url, apikey=apikey)

    # verify URL was added for 'known URL list '
        known_urls = zap.core.urls()

    #Run Ajax Spider to add all URl's for known hosts
    #runAjaxSpider(zap,target=target)



    #Run Active Scan and report the results
    runActiveScan(zap, target=target)



    shutOffDeamon(zap)

if __name__ == '__main__':
    main()



