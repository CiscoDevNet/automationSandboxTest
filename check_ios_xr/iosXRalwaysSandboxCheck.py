import requests
import datetime
requests.packages.urllib3.disable_warnings()
from requests.exceptions import Timeout
import base64
import ssl
from backports.ssl_match_hostname import match_hostname, CertificateError
from urllib.request import Request, urlopen, ssl, socket
from pyats.topology import loader
from genie.conf import Genie
from genie.abstract import Lookup
from ncclient import manager
import xmltodict
import paramiko


DEF_TIMEOUT = 10
SSH_PORT = 8181
NETCONF_PORT = 10000
XR_BASH_PORT = 8282
USER = "admin"
PASSWORD = "C1sco12345"
MAX_RETRIES = 2

def main():
    url = "https://sbx-iosxr-mgmt.cisco.com"

    #sandboxAvailability(url)
    checkNetconfConnections(url)
    checkSSHConnections(url)
    #checkSSlcertificate(url)

def sandboxAvailability(url):
    url = url + ":9443/webui/"
    try:
        response = requests.get(url, verify=False)
        if response.status_code != 200:
            print ("Sandbox ", url, " Status code ", response.status_code)
            #send notification to bot
            exit()
        return (response.status_code)
    except requests.exceptions.RequestException as e:
        print ("Connection error: ", e)
        exit()

def checkNetconfConnections(url):
    url = url.replace('https://', '')
    for _ in range(MAX_RETRIES):
        try:
            with manager.connect(
                    host=url,
                    port=str(NETCONF_PORT),
                    username=USER,
                    password=PASSWORD,
                    hostkey_verify=False,
                    look_for_keys=False
            ) as m:
                print("NETCONF Connected is {}".format(m.connected))

        # If unable to connect, fail test
        except Exception as e:
            print("Attempt number {} to connect with NETCONF failed.".format(_ + 1))
            print(e)
        else:
            break
    # If unable to connect, fail test
    else:
            print ("Failed to establish NETCONF connection to ", url)

def checkSSHConnections(url):
    url = url.replace('https://', '')
    client = paramiko.SSHClient()
    for _ in range(MAX_RETRIES):
        try:
            client.connect(hostname=url, username=USER, password=PASSWORD, port=SSH_PORT)
        except Exception as e:
            print("Attempt number {} to connect with SSH failed.".format(_ + 1))
            print(e)
        else:
            break
    # If unable to connect, fail test
    else:
        print("Failed to establish SSH connection to ", url)

def checkSSlcertificate(url):
    base_url = url.replace('https://', '')
    base_url = base_url.replace('/', '')
    print ("base_url", base_url)
    port = '443'

    hostname = base_url
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port)) as sock:
        try:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                #print("Sock", ssock.version())
                data = ssock.getpeercert()
                # print(ssock.getpeercert())
        except CertificateError:
            print("SSL certificate error ", url)
            # send notification to bot
            exit()


    date_time_str = data["notAfter"]

    date_time_obj = datetime.datetime.strptime(date_time_str, '%b %d %H:%M:%S %Y GMT')

    print('Date:', date_time_obj)
    currentTime = datetime.datetime.now()
    print (currentTime)
    certificateExpirationDate = date_time_obj - currentTime
    print (str(certificateExpirationDate))
    daysToExpire = str(certificateExpirationDate).split()[0]
    print (daysToExpire)
    if int(daysToExpire) <= 60:
        print("less then 60 days to expire SSL certificate for URL ", url)
        # send notification to bot

if __name__ == "__main__":
    main()
