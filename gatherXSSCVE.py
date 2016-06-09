#!/usr/bin/python

import urllib
import urllib2
import json
import hashlib
import os.path
import tempfile
import sys
import argparse
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
			headers = {'Authorization': htoken, 'Accept': "application/json"}
			randSleep = randint(0,1)
			sleep(randSleep)
			request = urllib2.Request(furl, None, headers)
			data = urllib2.urlopen(request)
			jdata = json.loads(data.read())
			#print json.dumps(jdata, sort_keys=True, indent=3, separators=(',', ': '))
			return jdata
		except urllib2.HTTPError, e:
			sys.stderr.write(scanurl +  " " + str(e) + "\n")
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
		print "I believe the other types of API Token has been removed, add a base64 of your key to /tmp/IXFtoken. To be fixed"
		exit()
		#apitype = "Bearer "
    else:
	    print "Support for Anonymous API has been removed, add a base64 of your key to /tmp/IXFToken. To be fixed"
	    #url = "https://api.xforce.ibmcloud.com/auth/anonymousToken"
	    #data = urllib2.urlopen(url)
	    #t = json.load(data)
	    #tokenf = open(mytempfile,"w")
            #token = str(t['token'])
            #tokenf.write(token)
	    #apitype = "Bearer "
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
    #Some signatures claim they cover over 100 vulnerabilites, these are rare and I don't really trust those signatures provide that much coverage
    if siglist['covers']['total_rows'] > 100:
	print "%s,%s,over 100 vulns covered,skipped" % (xpu,signame)
	#Flush the buffer because I am impaitent
	sys.stdout.flush()
	return None
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

#Argparse is much easier than the other tutorials I saw. I can work with this
parser = argparse.ArgumentParser(description="Query the IBM Xforce API to get a csv output of threats to covered CVEs. Perfect for the SIEM in your life")
method = parser.add_mutually_exclusive_group()
method.add_argument("-x", "--xpu",  help="Lookup XPU Number")
method.add_argument("-s", "--sig", help="Lookup Signature Name")
method.add_argument("-xl", "--xpulist",  help="Lookup XPU Numbers From List")
method.add_argument("-sl", "--siglist", help="Lookup Sigs From List")
args = parser.parse_args()
if args.xpu:
	#Add the XPU if it isn't there
	if args.xpu.find("XPU ") < 0:
		clean_xpu = "XPU " + str(args.xpu)
	else:
		clean_xpu = str(args.xpu)
	get_xpu_info(clean_xpu)
elif args.sig:
	get_sig_info(args.sig,"N/A")
elif args.xpulist:
	with open(args.xpulist) as f:
	    for line in f:
		line = line.rstrip('\n')
		#Add the XPU if it isn't there
		if args.xpu.find("XPU ") < 0:
			clean_xpu = "XPU " + str(args.xpu)
		else:
			clean_xpu = str(args.xpu)
		get_xpu_info(line)
elif args.siglist:
	with open(args.siglist) as f:
	    for line in f:
		line = line.rstrip('\n')
		get_sig_info(line,"N/A")
#Old Examples
#Example - getting a list of all XPU
#xpunumberlist = ["33.050","33.060","33.070","33.080","33.090","33.10","33.110","33.120","34.010","34.020","34.030","34.040","34.050","34.060","34.070","34.080","34.090","34.10","34.110","34.120","35.010","35.020","35.030","35.040","35.050","35.060","35.070","35.080","35.090","35.10","35.110","35.120","36.010","36.020","36.030","36.040"]
#
#for xpu in xpunumberlist:
#	get_xpu_info(str(xpu))
#End Example

#Example - getting all CVEs associated with one signature name
#get_sig_info("JavaObjectStream_TraxTemplates_Exec","manual")
#End Example
#get_sig_info("JavaObjectStream_TraxTemplates_Exec","manual")
