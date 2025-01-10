import requests

url = input("For which HTTP URL (http://www.inserturl.com) would you like to collect headers?: ")
response = requests.get(url)
headers = response.headers
print("HTTP Headers: ")

for header in headers:
    print(header + ":" + headers[header])