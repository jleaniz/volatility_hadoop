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
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LogFile(object):
    def __init__(self, path, parser, sc, destPath):
        self.localHdfs = '/mnt/hdfs'
        self.path = None
        self.parser = parser
        self.type = None
        self.sContext = sc
        self.destPath = destPath

    def parallelsave(self, localPath):

        rdd = self.sContext.newAPIHadoopFile('%s' %(self.path),
            'org.apache.hadoop.mapreduce.lib.input.TextInputFormat',
            'org.apache.hadoop.io.LongWritable',
            'org.apache.hadoop.io.Text',
            conf={'mapreduce.input.fileinputformat.input.dir.recursive':'true'}
        )

        #rdd = self.sContext.textFile('%s//*/*/*' % (self.path))
        if self.type is 'proxysg':
            parsed_rdd = rdd.map(lambda x: x[1]).mapPartitions(self.parser.parseBCAccessLogIter)
            df = parsed_rdd.toDF()
            df.write.parquet('%s/proxysgtest' % (self.destPath), mode='append', partitionBy=('date'))

        if self.type is 'iptables':
            parsed_rdd = rdd.map(lambda x: x[1]).mapPartitions(self.parser.parseIPTablesIter)
            df = parsed_rdd.toDF()
            #df.write.parquet('%s/fw' % (self.destPath), mode='append', partitionBy=('date'))
            df.write.saveAsTable('iptables', path='%s/fw' % (self.destPath), format='parquet', mode='append', partitionBy='date')

        if self.type is 'apacheAccessLog':
            parsed_rdd = rdd.map(lambda x: x[1]).mapPartitions(self.parser.parseApacheAL())
            df = parsed_rdd.toDF()
            df.write.parquet('%s/apache' % (self.destPath), mode='append', partitionBy=('date'))

        if self.type is 'bashlog':
            parsed_rdd = rdd.map(lambda x: x[1]).mapPartitions(self.parser.parseBash)
            df = parsed_rdd.toDF()
            logger.info('Saving DataFrame')
            df.write.parquet('%s/bashlog' % (self.destPath), mode='append', partitionBy=('date'))

        if self.type is 'ciscovpn':
            parsed_rdd = rdd.map(lambda x: x[1]).mapPartitions(self.parser.parseVPN)
            df = parsed_rdd.toDF()
            df.write.parquet('%s/ciscovpn' % (self.destPath), mode='append', partitionBy=('date'))

        print '=================='
        print "Completed task"
        print '=================='

    def saveLogByDate(self):
        sqlCtx = SQLContext(self.sContext)
        sqlCtx.setConf('spark.sql.parquet.compression.codec', 'snappy')
        print self.path
        self.parallelsave(self.path)

