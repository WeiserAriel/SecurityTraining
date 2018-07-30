'''
	This script tries to exposes SQL Injection for HTTP GET requests.
	For every url that has a parameter we replace each parameter value with FUZZ,
	while conserving the rest of the parameters values

	Example: http://192.168.113.130/dvwa/vulnerabilities/sqli/?id=userid&Submit=Submit#
	The script will try to inject  a given array for each one of the parameters ' ['\'']'
	in this case we will have two different injections:

	1. http://192.168.113.130/dvwa/vulnerabilities/sqli/?id=userid&Submit='
	2. http://192.168.113.130/dvwa/vulnerabilities/sqli/?id='&Submit=Submit#


'''


from copy import deepcopy
from urllib.parse import urlparse
import optparse
import requests
import sys

def abcd(url):
    errorssearch = ['Mysql','error in your SQL', 'SQL syntax']
    # injected values
    injections = ['\'' , '\"' , ';--']
    #write the results into a file
    f = open('results.txt','a+')
    a = urlparse(url=url)
    query = a.query.split('&')
    # get list of parameters from GET requests (each parameter is divided by '&' sign)

    paramsNumber = len(query)
    #for each GET parameter we are trying to inject all symbols from 'injection' list above
    while paramsNumber != 0:
        querys = deepcopy(query)
        querys[paramsNumber-1] = querys[paramsNumber-1].split('=')[0] + '=FUZZ'
        newq='&'.join(querys)
        url_to_test = a.scheme+'://'+a.netloc+a.path+'?'+newq
        paramsNumber-=1
        for inj in injections:
            req = requests.get(url_to_test.replace('FUZZ',inj))
            print (req.content)
            for err in errorssearch:
                if req.content.find(err) != -1:
                    res = req.url + ";" + err
                    f.write(res)
    f.close()

def request(context, flow):
    #Only if it is a query string
    q = flow.request.get_query()
    print (q)
    if q:
        injector(flow.request.url)
        flow.request.set_query(q)



def main():
    banner()

    #receving host_ip/port to start connection.
    parser = optparse.OptionParser(usage="""usage: ./SQLI_ErrorBased_detector.py [options] arg\n
                                         "Examples: ./SQLI_ErrorBased_detector.py -u http://192.168.113.130/dvwa/vulnerabilities/sqli/:
                                         """)
    parser.add_option("-u",  dest="url", type="string", help=" url for sql injection detector (http://somesite.com/admin)",)


    (options, args) = parser.parse_args()
    if( options.url is None ):
        parser.print_help()
        sys.exit(0)
    else:
    #Assigning variables:
        lurl = options.url
    try:
        abcd(url= lurl)
    except Exception as e:
        print("Couldn't send URL for injector\n" + str(e) + "\n")
        sys.exit(0)

def banner():
    print("\n*************************************************************************")
    print("\n*\t SQL injection detector - ERROR Based \n")
    print("\n*\t Written By: Ariel Weiser  ")
    print("\n*************************************************************************")

try:
    main()
except Exception as e:
    print("Main function couldn't be started! Exiting ! \n" + str(e) + "\n")
    sys.exit(0)



