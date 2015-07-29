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
import os
from pyspark.sql import SQLContext
from pyspark.sql.types import *


class LogFile(object):
    '''
    This class handles log files
    '''

    def __init__(self, path, parser, sc, destPath):
        self.localHdfs = '/mnt/hdfs'
        self.path = None
        self.parser = parser
        self.type = None
        self.sContext = sc
        self.destPath = destPath

    def saveLogByDate(self):
        '''
        This function will parse logs and save them
        to HDFS in parquet format partitioned by date

        The path containing the log files must be structured as follows:
        /path/to/logs/year/month/day/logfile.(gz,txt,etc)

        :param sContext: A Spark context
        :param path: The HDFS path containing the log files
        :return: None
        '''
        sqlCtx = SQLContext(self.sContext)
        sqlCtx.setConf('spark.sql.parquet.compression.codec', 'snappy')

        years = os.listdir(self.path)
        for year in years:
            months = os.listdir('%s/%s' % (self.path, year))
            for month in months:
                days = os.listdir('%s/%s/%s' % (self.path, year, month))
                for day in days:
                    if os.listdir('%s/%s/%s/%s' % (self.path, year, month, day)):
                        rdd = self.sContext.textFile('%s/%s/%s/%s' % (self.path, year, month, day))
                        if self.type is 'proxysg':
                            parsed_rdd = rdd.mapPartitions(self.parser.parseBCAccessLog)
                            df = parsed_rdd.toDF()
                            df.save('%s/proxysg/year=%s/month=%s/day=%s' % (self.destPath, year, month, day), 'parquet',
                                    'append')

                        if self.type is 'iptables':
                            parsed_rdd = rdd.mapPartitions(self.parser.parseIPTables)
                            df = parsed_rdd.toDF()
                            if 'onl' in self.path:
                                df.save('%s/onl/year=%s/month=%s/day=%s' % (self.destPath, year, month, day), 'parquet',
                                        'append')
                            if 'onbe' in self.path:
                                df.save('%s/onbe/year=%s/month=%s/day=%s' % (self.destPath, year, month, day), 'parquet',
                                        'append')
                            if 'off' in self.path:
                                df.save('%s/off/year=%s/month=%s/day=%s' % (self.destPath, year, month, day), 'parquet',
                                        'append')

                        if self.type is 'apacheAccessLog':
                            parsed_rdd = rdd.mapPartitions(self.parser.parseApacheAL())
                            df = parsed_rdd.toDF()
                            df.save('%s/apache/year=%s/month=%s/day=%s' % (self.destPath, year, month, day), 'parquet',
                                    'append')

                        if self.type is 'bashlog':
                            parsed_rdd = rdd.mapPartitions(self.parser.parseBash)
                            df = parsed_rdd.toDF()
                            df.save('%s/bashlog/year=%s/month=%s/day=%s' % (self.destPath, year, month, day), 'parquet',
                                    'append')

                    print 'Completed tasks for date: %s-%s-%s' % (year, month, day)
                    print 'Success: %s' % (self.parser.success.value)
                    self.parser.success = self.sContext.accumulator(0)
