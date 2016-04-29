#!/usr/bin/python

import urllib
import urllib2
import json
import hashlib
import os.path
import tempfile
import sys
from optparse import OptionParser
from random import randint
from time import sleep
from base64 import standard_b64decode
url = "https://api.xforce.ibmcloud.com"
def send_request(url, scanurl):
	while True:
		try:
			#Go get a token
			token, apitype= get_token()
			furl = url + urllib.quote(scanurl)
			htoken = apitype + token
			headers = {'Authorization': htoken,}
			randSleep = randint(0,1)
			sleep(randSleep)
			request = urllib2.Request(furl, None, headers)
			data = urllib2.urlopen(request)
			jdata = json.loads(data.read())
			#print json.dumps(jdata, sort_keys=True, indent=3, separators=(',', ': '))
			return jdata
		except urllib2.HTTPError, e:
			print scanurl +  " " +str(e)
			#Flush the buffer because I am impaitent
			sys.stdout.flush()
			if ("524:" in str(e)) or ("502:" in str(e)):
				#In large testing, the API interface returns 524 or 502 error when it is tired. sleep for a while then retry
				sleep(180)
			else:	
				return None


def get_token():
    #To avoid this function put your api key in /tmp/IXFtoken
    mytempfile = str(tempfile.gettempdir()) 
    mytempfile += "/IXFtoken"
    if os.path.isfile(mytempfile):
	    tokenf = open(mytempfile,"r")
	    token = tokenf.readline()
	   #Check the API key to see if it is a API key or token, either should work. API Keys are base64 encoded
	    try:
		standard_b64decode(token)
		apitype = "Basic "
	    except TypeError:
		apitype = "Bearer "
    else:
	    url = "https://api.xforce.ibmcloud.com/auth/anonymousToken"
	    data = urllib2.urlopen(url)
	    t = json.load(data)
	    tokenf = open(mytempfile,"w")
            token = str(t['token'])
            tokenf.write(token)
	    apitype = "Bearer "
    return (token,apitype) 


def get_sig_info(signame):
    apiurl = url + "/signatures/" 
    scanurl = signame
    siglist = send_request(apiurl, scanurl)
    rowz = siglist['covers']['total_rows']
    print "%s,%s" % (rowz,signame)
    sys.stdout.flush()


#Verification of the results collected with gatherXSSCVE. Compare collected vulnerabilities with signature coverage count
with open('signaturelist.txt') as f:
    for line in f:
	line = line.rstrip('\n')
	get_sig_info(line)
