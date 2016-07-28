# ibmxforceex.cheker.py
Python based client for IBM XForce Exchange
Thanks to Joerg Stephan for the base code.

Script used to build signature to CVE database of IBMXforce protection into CSV form. Useful for SIEM import

This is my first python project :-)

Added gatherXSSCVE.py
Also created cveFormatConvert to correct and issue with an eariler version of gatherXSSCVE.py

On August 1st 2016, X-Force changed the policy on API Calls. gatherXSSCVE can easily exceed the 5,000 a month quota. Be sure not to look up too many XPUs at once.

Excerpt from the notification:

Free Tier (Non-Commercial Use Only)

Provides the ability to query across the range of threat information from X-Force, including IPs, URLs, vulnerabilities, and malware.  This tier will allow usage of up to 5,000 records per month.   The 'record' metric is defined as a separate unit of information returned by an API call, e.g. URL categorization and reputation or WHOIS information on an IP address. The free tier is the easiest way to get started with X-Force Exchange API. 
