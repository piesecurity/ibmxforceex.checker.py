#!/usr/bin/python

import urllib
import urllib2
from optparse import OptionParser
import json
import hashlib
import os.path
import tempfile
import sys

url = "https://api.xforce.ibmcloud.com"
def send_request(url, scanurl):
	try:
		token= get_token()
		furl = url + urllib.quote(scanurl)
		htoken = "Bearer "+ token
		headers = {'Authorization': htoken,}
		request = urllib2.Request(furl, None, headers)
		data = urllib2.urlopen(request)

		jdata = json.loads(data.read())
		#print json.dumps(jdata, sort_keys=True, indent=3, separators=(',', ': '))
		return jdata
	except urllib2.HTTPError, e:
		print str(e)
		return None


def get_token():
    mytempfile = str(tempfile.gettempdir()) 
    mytempfile += "/IXFtoken"
    if os.path.isfile(mytempfile):
	    tokenf = open(mytempfile,"r")
	    token = tokenf.readline()
    else:
	    url = "https://api.xforce.ibmcloud.com/auth/anonymousToken"
	    data = urllib2.urlopen(url)
	    t = json.load(data)
	    tokenf = open(mytempfile,"w")
            token = str(t['token'])
            tokenf.write(token)
    return token 

def get_xpu_info(xpu):
    apiurl = url + "/signatures/xpu/" 
    scanurl = xpu 
    xpulist = send_request(apiurl, scanurl)
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
   # print json.dumps(siglist, sort_keys=True, indent=3, separators=(',', ': '))

def get_cve_info(vulid, signame, xpu):
    apiurl = url + "/vulnerabilities/" 
    scanurl = vulid
    vulidlist = send_request(apiurl, scanurl)
    #print json.dumps(vulidlist, sort_keys=True, indent=3, separators=(',', ': '))
    if "stdcode" in vulidlist:
	    for rowz in vulidlist['stdcode']:
		cve = rowz
		if "CVE" in cve:
			call_output(cve,vulid,signame,xpu)
    else:
    	call_output("NONE",vulid,signame,xpu)

def call_output(cve,vulid,signame,xpu):
	print "%s,%s,%s,%s" % (xpu,signame,vulid,cve)

#This section doesn't work
if "XPU" in sys.argv:
    get_xpu_info(sys.argv[1])
else: 
    get_xpu_info('XPU 35.060')
