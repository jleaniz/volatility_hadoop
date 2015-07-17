import argparse

import ingest.firewall.iptables as iptables
import ingest.bluecoat.proxysg as proxysg
import ingest.intelfeeds.alienvault_otx as aotx
import ingest.intelfeeds.openphish as openphish
import ingest.intelfeeds.c2_feeds as c2
import config.config as conf
from pyspark import SparkContext


def main():
    '''
    Main driver program. Takes some command line arguments
    :return: None
    '''
    cliparser = argparse.ArgumentParser(description='SRM Security Analytics')
    cliparser.add_argument('-i', '--ingest', action='append',
                           choices=['c2', 'openphish', 'alienvault_otx', 'bluecoat', 'iptables', 'imageinfo', 'pslist'],
                           required=True, help='Ingest raw logs into HDFS (saves Parquet files)')
    cliparser.add_argument('-s', '--path', action='append',
                           required=True,
                           help='Path to the log data. Subdirs must be structured as /year/month/day')
    args = cliparser.parse_args()

    '''Initialize Spark Context with default config'''
    appConfig = conf.Config()
    sc = SparkContext(conf=appConfig.setSparkConf())

    '''Loop through the cli arguments'''
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

    '''Stop the SparkContext'''
    sc.stop()


'''Main function'''
if __name__ == '__main__':
    main()
