import requests
import base64
import json

asus_ip = "192.168.50.1" # IP of router/gateway
account = "admin:opticalflow"

string_bytes = account.encode('ascii')
base64_bytes = base64.b64encode(string_bytes)
login = base64_bytes.decode('ascii')

url = 'http://{}/login.cgi'.format(asus_ip)
payload = "login_authorization=" + login
headers = {
    'user-agent': "asusrouter-Android-DUTUtil-1.0.0.245"
}
r = requests.post(url=url, data=payload, headers=headers)
token = r.json()['asus_token']
url='http://{}/appGet.cgi'.format(asus_ip)
payload = "hook={}".format('get_allclientlist()')
headers = {
    'user-Agent': "asusrouter-Android-DUTUtil-1.0.0.245",
    'cookie': 'asus_token={}'.format(token),
}
r = requests.post(url=url, data=payload, headers=headers)
meas = json.loads(r.text)

rssi = meas['get_allclientlist']['3C:7C:3F:66:4E:C0']['5G']['60:AA:EF:46:47:18']['rssi']

print('rssi=', rssi, 'dBm')









