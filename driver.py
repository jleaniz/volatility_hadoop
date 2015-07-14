import argparse
import srm.ingest.firewall.iptables as iptables
import srm.ingest.bluecoat.proxysg as proxysg
import srm.ingest.intelfeeds.alienvault_otx as aotx
import srm.ingest.intelfeeds.openphish as openphish
import srm.ingest.intelfeeds.c2_feeds as c2

from pyspark import SparkContext
from pyspark import SparkConf
from pyspark.sql import SQLContext
from pyspark.sql.types import *

def main():
	conf = (SparkConf()
		.setMaster("spark://mtl-srm-cdh01.ubisoft.org:7077")
		.setAppName("SRM-Analytics")
		.set("spark.driver.cores", "1")
		.set("spark.driver.maxResultSize", "200m")
		.set("spark.driver.memory", "512m")
		###########################################################
		#### If spark worker/executor java heap size is set in CHD
		###  and is lower these won't take effect
		.set("spark.worker.memory", "512m") 
		.set("spark.executor.memory", "512m")
		###########################################################
		.set("spark.executor.cores", "4")
		.set("spark.cores.max", "16")
		.set("spark.akka.timeout", "3000")
		.set("spark.network.timeout", "3000")
		.set("spark.core.connection.ack.wait.timeout", "3000")
		.set("spark.storage.memoryFraction", "0.5")
		.set("spark.default.parallelism", "48"))

	sc = SparkContext(conf = conf)

	cliparser = argparse.ArgumentParser(description='SRM Security Analytics')
	cliparser.add_argument('-i', '--ingest', action='append', 
		choices=['c2', 'openphish', 'alienvault_otx', 'bluecoat', 'iptables', 'imageinfo', 'pslist'],
		required=True, help='Ingest raw logs into HDFS (saves Parquet files)')
	cliparser.add_argument('-s', '--host', action='append',
		required=True, help='hostname to ingest logs from, has to match dir in /home/cloudera/fw/raw')

	args = cliparser.parse_args()

	for arg in args.ingest:
		if arg == 'iptables':
			for host in args.host:
				print 'Ingesting iptables logs for ', (host)
				iptables.save_log(sc, host)
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

	sc.stop()
	
if __name__ == '__main__':
	main()
