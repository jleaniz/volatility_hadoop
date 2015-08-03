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

from ingest.logfile import LogFile
import ingest.feeds as feeds
from lib.parser import Parser
from config import config as conf
from pyspark import SparkContext
from jobs import SparkSQLJob
import analytics.bluecoat as bluecoat
import datetime

def main():
    '''
    Main driver program. Takes some command line arguments
    :return: None
    '''
    cliparser = argparse.ArgumentParser(description='SRM Security Analytics')
    cliparser.add_argument('-i', '--ingest', action='append',
                           choices=['c2', 'openphish', 'alienvault_otx', 'proxysg', 'iptables', 'imageinfo', 'bashlog'
                                                                                                             'pslist'],
                           required=False, help='Ingest raw logs into HDFS (saves Parquet files)')
    cliparser.add_argument('-a', '--analytics', action='store_true',
                           required=False,
                           help='Run analytics functions')
    cliparser.add_argument('-p', '--path', action='append',
                           required=True,
                           help='Path to the log data. Subdirs must be structured as /year/month/day')
    args = cliparser.parse_args()

    '''Initialize Spark Context with default config'''
    appConfig = conf.Config()
    sc = SparkContext(conf=appConfig.setSparkConf())

    ''' LogFile and Parser objects
    Attributes will be defined after parsing "args" '''
    myParser = Parser()
    log = LogFile(path='', parser=myParser, sc=sc, destPath=None)

    '''Loop through the cli arguments'''
    if args.ingest:
        for arg in args.ingest:
            if arg == 'iptables':
                log.type = 'iptables'
                for path in args.path:
                    print 'Ingesting iptables logs for ', (path)
                    log.path = path
                    log.destPath = path.rsplit('/', 1)[0]
                    log.saveLogByDate()
            elif arg == 'proxysg':
                log.type = 'proxysg'
                for path in args.path:
                    print 'Ingesting Blue Coat ProxySG access logs...'
                    log.path = path
                    log.destPath = path.rsplit('/', 1)[0]
                    log.saveLogByDate()
            elif arg == 'bashlog':
                log.type = 'bashlog'
                for path in args.path:
                    print 'Ingesting bash logs...'
                    log.path = path
                    log.destPath = path.rsplit('/', 1)[0]
                    log.saveLogByDate()
            elif arg == 'alienvault_otx':
                print 'Updating local AlienVault OTX db...'
                feeds.updateAlienvaultOtx(sc)
            elif arg == 'openphish':
                print 'Updating local OpenPhish db...'
                feeds.updateOpenphish(sc)
            elif arg == 'c2':
                print 'Updating local c2 db...'
                feeds.updateC2Feeds(sc)

    if args.analytics:
        funcs = []
        arguments = [
            args.path[0], '100', datetime.date.today().year, datetime.date.today().month, datetime.date.today().day
        ]
        funcs.append(bluecoat.getClientsByTransfer)
        print funcs
        job = SparkSQLJob(sc=sc, funcs=funcs)
        for x in arguments:
            job.funcArgs.append(x)

        print job.funcArgs
        job.execute()

    '''Stop the SparkContext'''
    sc.stop()


'''Main function'''
if __name__ == '__main__':
    main()
