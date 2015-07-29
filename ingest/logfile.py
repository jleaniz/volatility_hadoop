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
import threading
import Queue

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

    def parallelsave(self, localPath, year, month, day, r_queue):
        if os.listdir('%s/%s/%s/%s' % (localPath, year, month, day)):
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

        r_queue.put((day, 'done'))

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
        localPath = self.localHdfs + self.path
        years = os.listdir(localPath)
        for year in years:
            months = os.listdir('%s/%s' % (localPath, year))
            for month in months:
                days = os.listdir('%s/%s/%s' % (localPath, year, month))
                for day in days:
                    q = Queue.Queue()
                    threads = [threading.Thread(target=self.parallelsave, args=(localPath,year,month,day,q)) for i in range(4)]
                    for thread in threads:
                        thread.start()

                    r = q.get()

                    print 'Completed tasks for date: %s-%s-%s' % (year, month, day)
                    print 'Success: %s' % (self.parser.success.value)
                    self.parser.success = self.sContext.accumulator(0)
