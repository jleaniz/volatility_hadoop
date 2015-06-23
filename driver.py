import argparse
import ingest.firewall.iptables as iptables
import ingest.bluecoat.proxysg as proxysg
import ingest.intelfeeds.alienvault_otx as aotx
import ingest.intelfeeds.openphish as openphish
import ingest.intelfeeds.c2_feeds as c2

from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *


def main():
	sc = SparkContext("local[8]", "SRMAnalytics", pyFiles=['srm.zip'])

	cliparser = argparse.ArgumentParser(description='SRM Security Analytics')
	cliparser.add_argument('-i', '--ingest', action='append', choices=['c2', 'openphish', 'alienvault_otx', 'bluecoat',
																	   'iptables', 'imageinfo', 'pslist'],
						   required=True, help='Ingest raw logs into HDFS (saves Parquet files)')
	args = cliparser.parse_args()
	# print args

	for arg in args.ingest:
		if arg == 'iptables':
			print 'Ingesting iptables logs...'
			iptables.save_log(sc)
		elif arg == 'bluecoat':
			print 'Ingesting Blue Coat ProxySG access logs...'
			proxysg.save_access_log(sc)
		elif arg == 'alienvault_otx':
			print 'Updating local AlienVault OTX db...'
			aotx.update_alienvault_otx(sc)
		elif arg == 'openphish':
			print 'Updating local OpenPhish db...'
			openphish.update_openphish(sc)
		elif arg == 'c2':
			print 'Updating local c2 db...'
			c2.update_c2_feeds(sc)


if __name__ == '__main__':
	main()
