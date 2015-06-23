import urllib2
import lib.parser as parser
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

def update_c2_feeds(sContext):
	sqlCtx = SQLContext(sContext)
	results = []
	urls = ['http://osint.bambenekconsulting.com/feeds/c2-masterlist.txt',
			'http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
			#'https://lists.malwarepatrol.net/cgi/getfile?receipt=f1434725867&product=8&list=dansguardian',
			'http://mirror1.malwaredomains.com/files/domains.txt',
			#'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist'
			#'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist',
			#'https://zeustracker.abuse.ch/blocklist.php?download=compromised',
			#'http://www.montanamenagerie.org/hostsfile/hosts.txt',
			'http://malc0de.com/bl/IP_Blacklist.txt'
			]

