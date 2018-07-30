'''
Using requests library we can make head requests, using 'http://httpbin.org/' for testing purposes
The HEAD method is identical to GET except that the server MUST NOT return a message-body in the response
The metainformation contained in the HTTP headers in response to a HEAD request SHOULD be identical to the information sent in response to a GET request.
'''
#!/usr/bin/env python
import requests

url = 'http://httpbin.org/ip'
r = requests.head(url= url )

print ("\n\n\nSending HEAD Request to: " + r.url)
print ('\nStatus Code is : ' + str(r.status_code) + '\n')

print ('\n\nServer Headers are :')
for header in r.headers:
    print ('\t' + header + ' : ' + r.headers[header] )
#we wont get the content because it is a head request
print("\n\nPrinting response body ( should be empty )" + r.text)
