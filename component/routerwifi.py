import requests
import base64
import json
import time

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
payload = "hook={}".format('netdev(appobj);')
headers = {
    'user-Agent': "asusrouter-Android-DUTUtil-1.0.0.245",
    'cookie': 'asus_token={}'.format(token),
}
r = requests.post(url=url, data=payload, headers=headers)
meas_1 = json.loads(r.text)
time.sleep(2)
r = requests.post(url=url, data=payload, headers=headers)
meas_2 = json.loads(r.text)
print(r.text)


tx = int(meas_2['netdev']['INTERNET_tx'], base=16) * 8 / 1024 / 1024/ 2
tx -= int(meas_1['netdev']['INTERNET_tx'], base=16) * 8 / 1024 / 1024/ 2
rx = int(meas_2['netdev']['INTERNET_rx'], base=16) * 8 / 1024 / 1024/ 2
rx -= int(meas_1['netdev']['INTERNET_rx'], base=16) * 8 / 1024 / 1024/ 2

tx1 = int(meas_2['netdev']['BRIDGE_tx'], base=16) * 8 / 1024 / 1024 / 2
tx1 -= int(meas_1['netdev']['BRIDGE_tx'], base=16) * 8 / 1024 / 1024 / 2
rx1 = int(meas_2['netdev']['BRIDGE_rx'], base=16) * 8 / 1024 / 1024 / 2 
rx1 -= int(meas_1['netdev']['BRIDGE_rx'], base=16) * 8 / 1024 / 1024 / 2

tx2 = int(meas_2['netdev']['WIRED_tx'], base=16) * 8 / 1024 / 1024 / 2
tx2 -= int(meas_1['netdev']['WIRED_tx'], base=16) * 8 / 1024 / 1024 / 2
rx2 = int(meas_2['netdev']['WIRED_rx'], base=16) * 8 / 1024 / 1024 / 2
rx2 -= int(meas_1['netdev']['WIRED_rx'], base=16) * 8 / 1024 / 1024 / 2

tx3 = int(meas_2['netdev']['WIRELESS0_tx'], base=16) * 8 / 1024 / 1024 / 2
tx3 -= int(meas_1['netdev']['WIRELESS0_tx'], base=16) * 8 / 1024 / 1024 / 2
rx3 = int(meas_2['netdev']['WIRELESS0_rx'], base=16) * 8 / 1024 / 1024 / 2
rx3 -= int(meas_1['netdev']['WIRELESS0_rx'], base=16) * 8 / 1024 / 1024 / 2

tx4 = int(meas_2['netdev']['WIRELESS1_tx'], base=16) * 8 / 1024 / 1024 / 2
tx4 -= int(meas_1['netdev']['WIRELESS1_tx'], base=16) * 8 / 1024 / 1024 / 2
rx4 = int(meas_2['netdev']['WIRELESS1_rx'], base=16) * 8 / 1024 / 1024 / 2
rx4 -= int(meas_1['netdev']['WIRELESS1_rx'], base=16) * 8 / 1024 / 1024 / 2

print('TX Mbit/s : ' + str(tx))
print('RX Mbit/s : ' + str(rx))

print('TX_Bridge Mbit/s : ' + str(tx1))
print('RX_Bridge Mbit/s : ' + str(rx1))

print('TX_Wired Mbit/s : ' + str(tx2))
print('RX_Wired Mbit/s : ' + str(rx2))

print('TX_Wireless0 Mbit/s : ' + str(tx3))
print('RX_Wireless0 Mbit/s : ' + str(rx3))

print('TX_Wireless1 Mbit/s : ' + str(tx4))
print('RX_Wireless1 Mbit/s : ' + str(rx4))

class RouterInfo:

    def __init__(self, ipaddress, username, password):
        """
        Create the object and connect with the router
        Parameters:
            ipaddress : IP Address of the router
            username : Root user name
            password : Password required to login
        """
        self.ip = ipaddress
        self.token = None
        self.__authenticate(username, password)

    def __authenticate(self, username, password):
        """
        Authenticate the object with the router
        Parameters:
            username : Root user name
            password : Password required to login
        """
        auth = "{}:{}".format(username, password).encode('ascii')
        logintoken = base64.b64encode(auth).decode('ascii')
        payload = "login_authorization={}".format(logintoken)
        headers = {
            'user-agent': "asusrouter-Android-DUTUtil-1.0.0.245"
        }
        try:
            r = requests.post(url='http://{}/login.cgi'.format(self.ip), data=payload, headers=headers).json()
        except:
            return False
        if "asus_token" in r:
            self.token = r['asus_token']
            return True
        else:
            return False

    def __get(self, command):
        """
        Private get method to execute a hook on the router and return the result
        Parameters:
            command : Command to send to the return
        :returns: string result from the router
        """
        if self.token:
            payload = "hook={}".format(command)
            headers = {
                'user-agent': "asusrouter-Android-DUTUtil-1.0.0.245",
                'cookie': 'asus_token={}'.format(self.token)
            }
            try:
                r = requests.post(url='http://{}/appGet.cgi'.format(self.ip), data=payload, headers=headers)
            except:
                return None
            return r.text
        else:
            return None

admin="admin"
pasword="opticalflow"
ip="192.168.50.1"
ri = RouterInfo(ip,admin,pasword)






