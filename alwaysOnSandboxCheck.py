import json
import sys
import requests
import time
from datetime import date
import datetime
from requests.auth import HTTPBasicAuth
requests.packages.urllib3.disable_warnings()
from requests.exceptions import Timeout
import base64
import ssl
from backports.ssl_match_hostname import match_hostname, CertificateError
from urllib.request import Request, urlopen, ssl, socket
from urllib.error import URLError, HTTPError


DEF_TIMEOUT = 10
USER_DNA = "devnetuser"
PASSWORD_DNA = "Cisco123!"

# Do we need to test all ports SSH, NETCONF, RESTCONF ?
# For some sandboxes in Instructions tub, we also see  - "you need to approve self-sign certificate", what to do with this?

def main():
    url = "https://sandboxdnac.cisco.com/"
    url = "https://parkbooking.com.ua/"
    IOS_XE_CSR = "https://ios-xe-mgmt.cisco.com:9443/webui/"
    ACI_Simulator = "https://sandboxapicdc.cisco.com"
    sdWan = "https://sandboxsdwan.cisco.com:8443/"
    #sdWan = "devnetuser/Cisco123!"

    #url = ACI_Simulator
    #sandboxAvailability(url)
    #checkSimpleRequest(url)
    checkSSlcertificate(url)

def sandboxAvailability(url):
    response = requests.get(url)
    if response.status_code != 200:
        #send notification to bot
        exit()
    return (response.status_code)

def checkSimpleRequest(url):
    postUrlDNA = url + "api/system/v1/auth/token"
    usrPasDna = USER_DNA + ":" + PASSWORD_DNA
    basicDNA = base64.b64encode(usrPasDna.encode()).decode()
    headers = {"Authorization": "Basic %s" % basicDNA,
                "Content-Type": "application/json;"}
    body_json = ""

    try:
        response = requests.post(postUrlDNA, data=body_json, headers=headers, verify=False, timeout=DEF_TIMEOUT)
    except Timeout as e:
        raise Timeout(e)
    tokenDNA = response.json()['Token']
    #print (tokenDNA)
    urlSimpleDNA = url + "api/v1/network-device/"

    headers = {'x-auth-token': tokenDNA}
    try:
        response = requests.get(urlSimpleDNA, headers=headers)
        #print (response.json())
        if response.status_code != 200:
            print("Error SimpleRequest status_code != 200")
            # send notification to bot
            exit()
    except Timeout as e:
        raise Timeout(e)
    try:
        b = response.json()['response'][0]['type']
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


# result = requests.post(url,
#       headers={'Content-Type':'application/json',
#                'Authorization': 'Bearer {}'.format(access_token)})


# def checkSimpleRequest(url):
#     postUrlDNA = url + "api/system/v1/auth/token"
#     tokenDNA = HTTPBasicAuth(USER_DNA, PASSWORD_DNA)
#     headers = {"Authorization": "Basic " + tokenDNA,
#                 "Content-Type": "application/json;"}
#     #body_json = {"name": TEAM_NAME}
#
#     try:
#         response = requests.post(postUrlDNA, headers=headers, verify=False, timeout=DEF_TIMEOUT)
#     except Timeout as e:
#         raise Timeout(e)
#     else:
#         response = response.json()
#         if 'errors' in response.keys():
#             raise BaseException('Bot API error: %s' % response['errors'][0]['description'])
#         else:
#             return response["id"]

def sandboxAvailability1(url):
    #print(data)
    #page 85 in guide
    try:
        hex = data["POST_params"]["{http://uri.actility.com/lora}payload_hex"]
        hex = "080900001edacfd8c20c37"
        print(hex)

        # print("Bytes ", bytes.fromhex(hex))
        # binary = str(bytes.fromhex(hex))
        byte0 = hex[:2]
        print("B ", byte0)
        byteBinary = "{0:08b}".format(int(byte0, 16))
        #byteBinary = "00000010"
        print("byteBinary ", byteBinary)
        print("byteBinary[0]", byteBinary[0], "byteBinary[1]", byteBinary[1], "byteBinary[4:8]", byteBinary[4:8])
        if byteBinary[:1] == "0":
            parkingSlot = 0
            # free
        else:
            parkingSlot = 1
            # occupied
        print("parkingSlot ", parkingSlot)
        if byteBinary[1] == "0":
            battery = "good"
        else:
            battery = "bad"
        print("battery ", battery)
        frameType = int(byteBinary[4:8], 2)
        print("frameType ", frameType)
        return (parkingSlot, battery, frameType)
    except IndexError:
        print("Error")
        return (False)

if __name__ == "__main__":
    main()
