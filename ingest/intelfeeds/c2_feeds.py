import urllib
import re
#import netaddr

#import lib.parser as parser
#from pyspark import SparkContext
#from pyspark.sql import SQLContext
#from pyspark.sql.types import *

def update_c2_feeds():
#	sqlCtx = SQLContext(sContext)
	results = []
	urls = ['http://osint.bambenekconsulting.com/feeds/c2-masterlist.txt',
			'http://rules.emergingthreats.net/fwrules/emerging-IPF-ALL.rules',
			'https://lists.malwarepatrol.net/cgi/getfile?'
			'http://mirror1.malwaredomains.com/files/domains.txt',
			'http://www.montanamenagerie.org/hostsfile/hosts.txt'
			]

	for url in urls:
		if 'montanamenagerie.org' in url:
			print 'Updating db from montanamenagerie.org'
			f = urllib.urlopen(url)
			data = f.read().split('\r\n')
			for line in data:
				element = line.split('\t')
				if '#' not in element:
					if len(element) >= 2:
						domain = element[1]
						#if domain not in results:
						results.append(domain)

		if 'malwaredomains.com' in url:
			print 'Updating db from malwaredomains.com'
			f = urllib.urlopen(url)
			data = f.read().split('\r\n')
			for line in data:
				element = line.split('\t')
				if len(element) >= 6:
					domain = element[2]
					#if domain not in results:
					results.append(domain)

		if 'emergingthreats.net' in url:
			print 'Updating db from emergingthreats.net'
			f = urllib.urlopen(url)
			data = f.read().split('\n')
			for line in data:
				acl = line.split()
				if len(acl) == 8:
					if re.search('(\d+.\d+.\d+.\d+)|(\d+.\d+.\d+.\d+\/\d+)', acl[5]):
						ip = acl[5]
						results.append(ip)
#						for ipaddr in netaddr.IPNetwork(ip):
#							if ipaddr not in results:
#							results.append(ipaddr)

		if 'bambenekconsulting.com' in url:
			print 'Updating db from bambenekconsulting.com'
			f = urllib.urlopen(url)
			data = f.read().split('\n')
			for line in data:
				domain = line.split(',')[0].strip()
				#if domain not in results:
				results.append(domain)

		if 'malwarepatrol.net' in url:
			print 'Updating db from malwarepatrol.net'
			params = urllib.urlencode({'receipt': 'f1434725867', 'product': 8, 'list': 'dansguardian'})
			f = urllib.urlopen(url, params)
			data = f.read().split()
			for line in data:
				domain = line.split('/')[0].strip()
				#if domain not in results:
				results.append(domain)

	return list(set(results))

if __name__ == '__main__':
	feed = update_c2_feeds()
	print len(feed)


