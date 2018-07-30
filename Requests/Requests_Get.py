'''
1.with requests library we can make get/post requests, You can add auth to provide authentication credentials
parameters to provide the url parameters
Written By : Ariel Weiser
'''
#!/usr/bin/env python
import requests

#add parameters for GET Request:
payload = {'url':'http://www.edge-security.com'}

url = 'https://auth-demo.aerobaticapp.com/protected-custom/'
#Example for GET request with Basic authentication:
print("Sending GET Request to:" + str(url)+"\n" )
r = requests.get(url=url , auth=('aerobatic', 'aerobatic'))
print("r.status_code = " + str(r.status_code) +"\n")


#Modify Get request headers:
myHeaders = {"user-agent" :  "Mozilla/5.0", "accept-language" :"en-US"}
print("Sending GET Request with new headers to:" + str(url)+"\n" )
r = requests.get(url=url, headers=myHeaders)
print("r.status_code = " + str(r.status_code) +"\n")

#Checking if request was redirected:
for history in r.history:
    print(str(history.status_code) + ' : ' + history.url)
