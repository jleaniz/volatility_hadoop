import ingest.firewall.iptables as iptables
import ingest.bluecoat.proxysg as proxysg
import argparse
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

def main():
	sc = SparkContext("local[8]", "SRMAnalytics", pyFiles=['srm.zip'])

	cliparser = argparse.ArgumentParser(description='SRM Security Analytics')
	cliparser.add_argument('-i','--ingest', action='append', choices=['bluecoat', 'iptables', 'imageinfo', 'pslist'], required=True, help='Ingest raw logs into HDFS (saves Parquet files)')
	args = cliparser.parse_args()
	#print args

	for arg in args.ingest:
		if arg == 'iptables':
			print 'Ingesting iptables logs...'
			iptables.save_log(sc)
		elif arg == 'bluecoat':
			print 'Ingesting Blue Coat ProxySG access logs...'
			proxysg.save_access_log(sc)

	sc.stop()

if __name__ == '__main__':
	main()
