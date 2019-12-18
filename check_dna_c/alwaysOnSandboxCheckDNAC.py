import requests
import datetime
requests.packages.urllib3.disable_warnings()
from requests.exceptions import Timeout
import base64
import ssl
from backports.ssl_match_hostname import match_hostname, CertificateError
from urllib.request import Request, urlopen, ssl, socket


DEF_TIMEOUT = 10
USER_DNA = "devnetuser"
PASSWORD_DNA = "Cisco123!"
f = open("error.txt", "w")

def main():
    url = "https://sandboxdnac.cisco.com/"
    f.write("Error test")
    f.close()
    sandboxAvailability(url)
    checkSimpleRequest(url)
    checkSSlcertificate(url)

def sandboxAvailability(url):
    response = requests.get(url)
    if response.status_code != 200:
        f.write("response.status_code != 200 ")
        f.write(response.status_code)
        f.close()
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
    urlSimpleDNA = url + "api/v1/network-device/"

    headers = {'x-auth-token': tokenDNA}
    try:
        response = requests.get(urlSimpleDNA, headers=headers)
        #print (response.json())
        if response.status_code != 200:
            f.write("Error SimpleRequest status_code != 200")
            f.close()
            exit()
    except Timeout as e:
        raise Timeout(e)
    try:
        b = response.json()['response'][0]['type']
    except IndexError:
        f.write("Error SimpleRequest index")
        # send notification to bot
        exit()

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
