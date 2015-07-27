#
# This file is part of BDSA (Big Data Security Analytics)
#
# BDSA is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# BDSA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with BDSA.  If not, see <http://www.gnu.org/licenses/>.
#
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
    cliparser.add_argument('-p', '--path', action='append',
                           required=True,
                           help='Path to the log data. Subdirs must be structured as /year/month/day')
    args = cliparser.parse_args()

    '''Initialize Spark Context with default config'''
    appConfig = conf.Config()
    sc = SparkContext(conf=appConfig.setSparkConf())

    '''Loop through the cli arguments'''
    for arg in args.ingest:
        if arg == 'iptables':
            for path in args.path:
                print 'Ingesting iptables logs for ', (path)
                iptables.save_log(sc, path)
        elif arg == 'bluecoat':
            for path in args.path:
                print 'Ingesting Blue Coat ProxySG access logs...'
                proxysg.save_access_log(sc, path)
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
