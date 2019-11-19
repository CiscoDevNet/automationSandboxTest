import requests
import datetime
requests.packages.urllib3.disable_warnings()
from requests.exceptions import Timeout
import base64
import ssl
from backports.ssl_match_hostname import match_hostname, CertificateError
from urllib.request import Request, urlopen, ssl, socket


DEF_TIMEOUT = 10
USER_DNA = "admin"
PASSWORD_DNA = "ciscopsdt"

def main():
    url = "https://sandboxapicdc.cisco.com/"

    sandboxAvailability(url)
    checkSimpleRequest(url)
    #checkSSlcertificate(url)

def sandboxAvailability(url):
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

def checkSimpleRequest(url):
    postUrl = url + "api/aaaLogin.json"
    headers = {"Content-Type": "application/json;"}
    body_json = '''
    {
        "aaaUser": {
            "attributes": {
                "name": "admin",
                "pwd": "ciscopsdt"
            }
        }
    }
    '''
    s = requests.session()
    try:
        response = s.post(postUrl, data=body_json, headers=headers, verify=False, timeout=DEF_TIMEOUT)
        print (response.text)
    except Timeout as e:
        raise Timeout(e)
    token = response.json()['imdata'][0]['aaaLogin']['attributes']['token']
    urlSimple = url + "api/class/fvAp.json?"

    try:
        response = s.get(urlSimple, verify=False)
        if response.status_code != 200:
            print("Error SimpleRequest status_code != 200")
            # send notification to bot
            exit()
    except Timeout as e:
        raise Timeout(e)
    # Error sample {'totalCount': '1', 'imdata': [{'error': {'attributes': {'code': '403', 'text': 'Need a valid webtoken cookie (named APIC-Cookie) or a signed request with signature in the cookie APIC-Request-Signature for all REST API requests'}}}]}
    try:
        b = response.json()['imdata'][0]['fvAp']
    except IndexError:
        print("Error SimpleRequest index")
        # send notification to bot
        exit()

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
