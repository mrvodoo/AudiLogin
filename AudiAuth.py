import requests
import re
import logging
import AudiCredentials
from http.client import HTTPConnection

#Logging
#log = logging.getLogger('urllib3')  # works
#log.setLevel(logging.DEBUG)  # needed
#fh = logging.FileHandler("requests.log")
#log.addHandler(fh)


#Need to be moved to an seperate file - Credentials
email = AudiCredentials.username
password = AudiCredentials.password

#URLs
baseURL = "https://identity.vwgroup.io"
authorizeURL = baseURL + "/oidc/v1/authorize"
identifierURL = baseURL + "/signin-service/v1/09b6cbec-cd19-4589-82fd-363dfa8c24da@apps_vw-dilab_com/login/identifier"
authenticateURL = baseURL + "/signin-service/v1/09b6cbec-cd19-4589-82fd-363dfa8c24da@apps_vw-dilab_com/login/authenticate"
AudiTokenURL = "https://app-api.my.audi.com/myaudiappidk/v1/token"
VWTokenURL = "https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth/mobile/oauth2/v1/token"


#Auth Code Params
response_type = "response_type=code"
client_id = "client_id=09b6cbec-cd19-4589-82fd-363dfa8c24da%40apps_vw-dilab_com"
VW_grant_type = "id_token"
VW_scope = "sc2:fal"
Audi_client_id = "09b6cbec-cd19-4589-82fd-363dfa8c24da@apps_vw-dilab_com"
Audi_grant_type = "authorization_code"
Audi_redirect_uri = "myaudi:///"
Audi_response_type = "token id_token"
redirect_uri = "redirect_uri=myaudi%3A%2F%2F%2F"
scope = "scope=address%20profile%20badge%20birthdate%20birthplace%20nationalIdentifier%20nationality%20profession%20email%20vin%20phone%20nickname%20name%20picture%20mbb%20gallery%20openid"
state = "state=7f8260b5-682f-4db8-b171-50a5189a1c08"
nonce = "nonce=583b9af2-7799-4c72-9cb0-e6c0f42b87b3"
prompt = "prompt=login"
ui_locales = "ui_locales=de-DE%20de"
headerssession = {
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json;charset=UTF-8',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36',
    }
loginheaders = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\
        image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36',
    'Referer': 'https://identity.vwgroup.io/signin-service/v1/signin/09b6cbec-cd19-4589-82fd-363dfa8c24da@apps_vw-dilab_com?relayState=1306273173f6e83fc92191ebf1b44c69cbaab41f', 
    }
vwheaders = {
    'X-App-Version': '3.14.0',
    'X-App-Name' : 'myAudi',
    'X-Client-Id': '77869e21-e30a-4a92-b016-48ab7d3db1d8',
}


#Get authorization code
#HTTPConnection.debuglevel = 1
authCodeReq= authorizeURL+"?"+response_type+"&"+client_id+"&"+redirect_uri+"&"+scope+"&"+state+"&"+nonce+"&"+prompt+"&"+ui_locales
s = requests.Session()
r=s.get(authCodeReq, headers=headerssession, allow_redirects=False)
signinuserURL=r.headers.get('Location')
#print (signinURL)

#Start sign in
#HTTPConnection.debuglevel = 1
r=s.get(signinuserURL, headers=headerssession, allow_redirects=False)
html = (r.text)
csrf = re.findall(r'name="_csrf" value="([a-z0-9\-]*)"', html) [0]
relaystate = re.findall(r'name="relayState" value="([a-z0-9\-]*)"', html) [0]
hmac = re.findall(r'name="hmac" value="([a-z0-9\-]*)"', html) [0]
payload = {
    '_csrf':csrf, 
    'relayState':relaystate, 
    'hmac':hmac, 
    'email':email,
    }

#print (payload)

#Auth - 4 - Sign-in process: username
#HTTPConnection.debuglevel = 1
r=s.post(identifierURL, headers=loginheaders, data=payload, allow_redirects=False)
signinpasswordURL = baseURL + r.headers.get('Location')


#Sign in - password page
#HTTPConnection.debuglevel = 1
r=s.get(signinpasswordURL, headers=headerssession, allow_redirects=False)
html = (r.text)
csrf = re.findall(r'name="_csrf" value="([a-z0-9\-]*)"', html) [0]
relaystate = re.findall(r'name="relayState" value="([a-z0-9\-]*)"', html) [0]
hmac = re.findall(r'name="hmac" value="([a-z0-9\-]*)"', html) [0]
payload = {
    '_csrf':csrf, 
    'relayState':relaystate,
    'email':email, 
    'hmac':hmac, 
    'password':password,
    }
#print (payload)

#Sign in - pass
#HTTPConnection.debuglevel = 1
r=s.post(authenticateURL, headers=loginheaders, data=payload, allow_redirects=False)
signinContinueURL = r.headers.get('Location')

#print (signinContinueURL)

#Sign in - continue
#HTTPConnection.debuglevel = 1
r=s.get(signinContinueURL, headers=loginheaders, allow_redirects=False)
signinConsentURL = r.headers.get('Location')

#print (signinConsentURL)

#Sign in - consent
#HTTPConnection.debuglevel = 1
r=s.get(signinConsentURL, headers=loginheaders, allow_redirects=False)
signinCallbackURL = r.headers.get('Location')

#print(signinCallbackURL)

#ASign in - callback
#HTTPConnection.debuglevel = 1
r=s.get(signinCallbackURL, headers=loginheaders, allow_redirects=False)
location = r.headers.get('Location')
Audi_authcode = re.findall(r'code=(.*)', location) [0]
#print (Audi_authcode)

#Get Audi API token
#HTTPConnection.debuglevel = 1
payload={
    'client_id': Audi_client_id,
    'grant_type': Audi_grant_type,
    'code': Audi_authcode,
    'redirect_uri': Audi_redirect_uri,
    'response_type': Audi_response_type,
}
r=requests.post(AudiTokenURL, headers=loginheaders, data=payload, allow_redirects=False)
body = (r.json())
audi_access_token = body ['access_token']
audi_refresh_token = body ['refresh_token']
audi_id_token = body ['id_token']

#print(body)
#print(audi_access_token)
#print(audi_refresh_token)
#print(audi_id_token)

#Get VW API token
#HTTPConnection.debuglevel = 1
payload={
    'grant_type': VW_grant_type,
    'token': audi_id_token,
    'scope': VW_scope,
}
r=requests.post(VWTokenURL, headers=vwheaders, data=payload, allow_redirects=False)
body = (r.json())

VW_access_token = body ['access_token']
VW_refresh_token = body ['refresh_token']

print(VW_access_token)
