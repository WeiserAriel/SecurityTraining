'''
with requests library we can make post requests, You will need to fill in the data variable with the credentials
using 'http://httpbin.org/' for testing purposes
Written By Ariel Weiser
'''
import requests

#add parameters to the post request inside the body
value = {"custname": "customer",
"custtel": "+972548006662",
"custemail":"email@gmail.com",
"size":"small",
"topping":"onion",
"delivery": "11:00",
"comments": "This is an example of Post request" }

url = "http://httpbin.org/post"
r = requests.post(url= url, data=value)

print ("\n\n\nSending Post Request to: " + r.url)
print ('\nStatus Code is : ' + str(r.status_code) + '\n')

print ('\n\nServer Headers are :')
for header in r.headers:
    print ('\t' + header + ' : ' + r.headers[header] )

print("Print Response contect \n")
print (r.text)