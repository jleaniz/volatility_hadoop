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
    def __init__(self, path, parser, sc, spark):
        self.path = None
        self.parser = parser
        self.type = None
        self.sContext = sc
        self.sparkSession = spark

    def parallelsave(self):


        rdd = self.sContext.newAPIHadoopFile('%s' %(self.path),
            'org.apache.hadoop.mapreduce.lib.input.TextInputFormat',
            'org.apache.hadoop.io.LongWritable',
            'org.apache.hadoop.io.Text',
            conf={'mapreduce.input.fileinputformat.input.dir.recursive':'true'}
        )

        if self.type is 'proxysg':
            parsed_rdd = rdd.map(lambda x: x[1]).mapPartitions(self.parser.parseBCAccessLogIter)
            df = self.sparkSession.createDataFrame(parsed_rdd)
            df.coalesce(256).write.saveAsTable('dw_srm.proxysg', format='parquet', mode='append', partitionBy='date')

        if self.type is 'iptables':
            parsed_rdd = rdd.map(lambda x: x[1]).mapPartitions(self.parser.parseIPTablesIter)
            df = self.sparkSession.createDataFrame(parsed_rdd)
            df.coalesce(256).write.saveAsTable('dw_srm.fw', format='parquet', mode='append', partitionBy='date')

        if self.type is 'apacheAccessLog':
            parsed_rdd = rdd.map(lambda x: x[1]).mapPartitions(self.parser.parseApacheAL())
            df = self.sparkSession.createDataFrame(parsed_rdd)
            df.coalesce(256).write.saveAsTable('dw_srm.apache', format='parquet', mode='append', partitionBy='date')

        if self.type is 'bashlog':
            parsed_rdd = rdd.map(lambda x: x[1]).mapPartitions(self.parser.parseBash)
            logger.info('Saving DataFrame')
            df = self.sparkSession.createDataFrame(parsed_rdd)
            df.coalesce(256).write.saveAsTable('dw_srm.bash', format='parquet', mode='append', partitionBy='date')

        if self.type is 'ciscovpn':
            parsed_rdd = rdd.map(lambda x: x[1]).mapPartitions(self.parser.parseVPN)
            df = self.sparkSession.createDataFrame(parsed_rdd)
            df.coalesce(256).write.saveAsTable('dw_srm.vpn', format='parquet', mode='append', partitionBy='date')

        print '=================='
        print "Completed task"
        print '=================='

    def saveLogByDate(self):
        sqlCtx = SQLContext(self.sContext)
        sqlCtx.setConf('spark.sql.parquet.compression.codec', 'snappy')
        print self.path
        self.parallelsave()

