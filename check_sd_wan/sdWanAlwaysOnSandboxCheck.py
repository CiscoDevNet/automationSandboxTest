import requests
import datetime
requests.packages.urllib3.disable_warnings()
from requests.exceptions import Timeout
import base64
import ssl
from backports.ssl_match_hostname import match_hostname, CertificateError
from urllib.request import Request, urlopen, ssl, socket
from viptela.viptela import Viptela


DEF_TIMEOUT = 10
USER = "devnetuser"
PASSWORD = "Cisco123!"
f = open("error.txt", "w")

def main():
    url = "https://sandboxsdwan.cisco.com"

    sandboxAvailability(url)
    checkSimpleRequest(url)
    checkSSlcertificate(url)
    f.close()

def sandboxAvailability(url):
    response = requests.get(url, verify=False, timeout=DEF_TIMEOUT)
    if response.status_code != 200:
        f.write("Sandbox " + url + " Status code " + str(response.status_code) + "\n")
        f.close()
        #send notification to bot
        exit()
    return (response.status_code)

def checkSimpleRequest(url):
    vmanage = Viptela(user=USER,user_pass=PASSWORD,
        vmanage_server=url,vmanage_server_port=8443)
    try:
        devices = vmanage.get_all_devices()
        print (devices)
    except:
        f.write("Simple request (vmanage.get_all_devices()) error" + url)
        f.close()

def checkSSlcertificate(url):
    base_url = url.replace('https://', '')
    base_url = base_url.replace('/', '')
    #print ("base_url", base_url)
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
            f.write("SSL certificate error ")
            f.close()
            # send notification to bot
            exit()


    date_time_str = data["notAfter"]

    date_time_obj = datetime.datetime.strptime(date_time_str, '%b %d %H:%M:%S %Y GMT')

    #print('Date:', date_time_obj)
    currentTime = datetime.datetime.now()
    #print (currentTime)
    certificateExpirationDate = date_time_obj - currentTime
    #print (str(certificateExpirationDate))
    daysToExpire = str(certificateExpirationDate).split()[0]
    #print (daysToExpire)
    if int(daysToExpire) <= 60:
        f.write("less then 60 days to expire SSL certificate for URL ")
        f.close()
        exit()

if __name__ == "__main__":
    main()
