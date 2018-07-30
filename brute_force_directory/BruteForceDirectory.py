import requests
from threading import Thread
import sys
import time
import optparse
import re
from hashlib import md5
import colorama
from colorama import Fore
import selenium

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

'''
Note - dictionary list for 'Directory brute force' should contain inputs in that syntax '<directory_name>+backslash'
relevant resposnse code are '200'.

for filenames search use this syntax ' <filename> + .php/.html
relevant responses are '200' and '302'. 
'''


def banner():
    print("\n*************************************************************************")
    print("\n*\t Brute Force Directory script")
    print("\n*\t Written By: Ariel Weiser  ")
    print("\n*************************************************************************")



class request_performer(Thread):
    def __init__(self, guess, url, hidecode):
        Thread.__init__(self)
        try:
            self.guess = guess.split("\n")[0]
            self.new_url = url.replace('GUESS', self.guess)
            self.url = url
            self.hidecode = hidecode

        except Exception as e:
            print (e)

    def run(self):
        try:
            start = time.time()
            r = requests.get(self.new_url)
            elaptime = time.time()

            #total time for request/response interval
            totaltime = str(elaptime - start)

            #getting number of lines
            try:
                content_str = bytes.decode(r.content)
                lines = content_str.count("\n")
            except Exception as e:
                print(e)
                sys.exit(0)

            #getting number of characters
            chars = str(len(content_str))

            #getting numbers of words
            wordsNumber = str(len(re.findall("\S+", content_str)))

            #parsing status code for response
            if r.history != []:
                first = r.history[0]
                code = str(first.status_code)
            else:
                code = str(r.status_code)
            #running MD5 function to distinguish between responses
            hash = md5(chars.encode('utf-8')).hexdigest()

            #User can filter by response code
            if self.hidecode != code:
                #if request for 'new_url' succeeded i'm using PhantomJS to take a screen shot
                if '200' <= code < '300':
                    dcap = dict(DesiredCapabilities.PHANTOMJS)
                    driver = webdriver.PhantomJS(desired_capabilities=dcap)
                    time.sleep(2)
                    driver.set_window_size(1024, 768)
                    driver.get(self.url)
                    driver.save_screenshot(self.word+".png")
                    #"Time" + "\t\t\t" + "Code" + "\tChars \t guesses \tLines \t MD5 \t\t\t\t\t String"

                    '''
                     print ("""-------------------------------------------------------------------------------------------------------------
                             Time + \t\t\t + Code + \tChars \t guesses \tLines \t MD5 \t\t\t\t\t String
                             -------------------------------------------------------------------------------------------------------------""")
                    '''
                    print (str(totaltime) + "  \t" + str(code)+ "\t\t\t" + str(chars) + "\t\t" + str(wordsNumber) + "\t\t\t" + str(lines) + "\t" + str(hash) + "\t"+ str(self.guess))
                elif '400' <= code < '500':
                    print (str(totaltime) + "  \t" + str(code) + "\t\t\t" + str(chars) + " \t\t" + str(wordsNumber) + "\t\t\t" + str(lines) + "\t"  + str(hash) + "\t" + str(self.guess))
                elif '300' <= code < '400':
                    print (str(totaltime) + "  \t" + str(code) + "\t\t\t" + str(chars) + "\t\t" + str(wordsNumber) + "\t\t\t" + str(lines) + "\t" + str(hash) + "\t" + str(self.guess))
                else:
                    # Here we remove one thread from the counter
                    i[0] = i[0] - 1
        except Exception as e:
            print (e)


def main():
    banner()

    #receving host_ip/port to start connection.
    parser = optparse.OptionParser(usage="""usage: ./BruteForceDirectory.py [options] arg\n
                                         "Examples:
                                         ./BruteForceDirectory.py -w http://www.example.com/GUESS -t 5 -f filenames.txt -c 404 \n""")
    parser.add_option("-w",  dest="url", type="string", help=" url (http://somesite.com/admin)",)
    parser.add_option("-t", dest="threads", help="number of threads")
    parser.add_option("-f", dest="dictionary", help="dictionary file with user guesses")
    parser.add_option("-c", dest="hidecode", help="HTTP response code to hide ( ex: 404 )")

    (options, args) = parser.parse_args()
    if ( (options.url is None) | (options.threads is None) | ( options.dictionary is None) ):
        parser.print_help()
        sys.exit(0)
    else:
    #Assigning variables:
        lurl = options.url
        lthreads = options.threads
        ldirectory = options.dictionary
    if options.hidecode is None:
        lhidecode = ""
    else:
        lhidecode = options.hidecode
    try:
        f = open(ldirectory, "r")
        guesses = f.readlines()
        #remove empty lines if any from 'guess' and delete newlines if needed.
        ConvertGusses = []
        for guess in guesses:
            if guess  == '\n':
                continue
            else:
                tmp = str(guess).replace('\n', '')
                ConvertGusses.append(tmp)

    except:
        print("Failed opening file:" + ldirectory +"\n")
        sys.exit()

    launcher_thread(ConvertGusses, lthreads, lurl, lhidecode)


def launcher_thread(guesses, threads, url, hidecode):
    global i
    i = []
    resultlist = []
    i.append(0)
    print ("""-------------------------------------------------------------------------------------------------------------
     Time  \t\t\t  Code  \t\tChars \t\t words \t\tLines \t\t\t\t MD5 \t\t\t\t\t String
     -------------------------------------------------------------------------------------------------------------""")
    while len(guesses):
        try:
            if i[0] < int(threads):
                guess = guesses.pop(0)
                i[0] = i[0] + 1
                thread = request_performer(guess, url, hidecode)
                thread.start()

        except KeyboardInterrupt:
            print ("script interrupted  by user. Finishing attack..")
            sys.exit()
        thread.join()
    return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print ("script interrupted by user, killing all threads..!!")