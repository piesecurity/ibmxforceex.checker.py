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

def get_xpu_info(xpu):
    apiurl = url + "/signatures/xpu/" 
    scanurl = xpu 
    xpulist = send_request(apiurl, scanurl)
    if xpulist == None:
	return None	
    for item in xpulist['rows']:
	signame = item['pamName']
	get_sig_info(signame, xpu)

def get_sig_info(signame, xpu):
    apiurl = url + "/signatures/" 
    scanurl = signame
    siglist = send_request(apiurl, scanurl)
    for rowz in siglist['covers']['rows']:
	#Set rows as a new variable so it knows there is a dictionary	
	x = rowz
	#Convert the number to a string"
	get_cve_info (str(x['xfdbid']), signame, xpu)

def get_cve_info(vulid, signame, xpu):
    apiurl = url + "/vulnerabilities/" 
    scanurl = vulid
    vulidlist = send_request(apiurl, scanurl)
    if "stdcode" in vulidlist:
	    for rowz in vulidlist['stdcode']:
		cve = rowz
		if "CVE" in cve:
			call_output(cve,vulid,signame,xpu)
    else:
	#Write "NONE" if there just isn't a CVE number with a vulid. It happens sometimes
    	call_output("NONE",vulid,signame,xpu)
def call_output(cve,vulid,signame,xpu):
	print "%s,%s,%s,%s" % (xpu,signame,vulid,cve)
	#Flush the buffer because I am impaitent
	sys.stdout.flush()

#This section doesn't work
#if "XPU" in sys.argv:
#    get_xpu_info(sys.argv[1])
#else: 
#a    get_xpu_info('XPU 35.060')


#Example - getting a list of all XPU
xpunumberlist = ["33.050","33.060","33.070","33.080","33.090","33.10","33.110","33.120","34.010","34.020","34.030","34.040","34.050","34.060","34.070","34.080","34.090","34.10","34.110","34.120","35.010","35.020","35.030","35.040","35.050","35.060","35.070","35.080","35.090","35.10","35.110","35.120","36.010","36.020","36.030","36.040"]

for xpu in xpunumberlist:
	get_xpu_info(str(xpu))
#End Example

#Example - getting all CVEs associated with one signature name
#get_sig_info("JavaObjectStream_TraxTemplates_Exec","manual")
#End Example
