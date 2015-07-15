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
