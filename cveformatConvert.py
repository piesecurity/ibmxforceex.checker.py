#!/usr/bin/python
#This script converts the name,signature list to a different format. Only Names, and all CVEs on new lines

import csv
with open ("ibm-iss-signatures.csv", "r") as f:
	reader = csv.DictReader(f)
	#defaultReader = reader
	siglist = []
	for row in reader:
		siglist.append(row['Name'])
	for sig in siglist:
		f.seek(0)
		#Fseek resets the position in the CSV
		lineCVE = ""
		#with open ("ibm-iss-signatures.csv", "r") as f2f:
		#reader2 = csv.DictReader(f)
		for row in reader:
	#	print searcher.line_num
			if sig == row['Name']:
				lineCVE = lineCVE + row['CVE'] + ","
		#Remove the list , from the CVE
		lineCVE = lineCVE[:-1]
		print "%s,\"%s\"" % (sig,lineCVE)
