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
from pyspark.streaming import StreamingContext, StreamingListener
from pyspark.sql import SQLContext, SparkSession
from pyspark.sql.types import Row
from pyspark import SparkContext
from lib.parser import Parser
from config import config as conf
import logging
import datetime

logging.basicConfig(level=logging.WARN)
logger = logging.getLogger('BDSA HDFS Streaming')
global last_updated


class batchInfoCollector(StreamingListener):
    def __init__(self):
        super(StreamingListener, self).__init__()
        self.batchInfosCompleted = []
        self.batchInfosStarted = []
        self.batchInfosSubmitted = []

    def onBatchSubmitted(self, batchSubmitted):
        self.batchInfosSubmitted.append(batchSubmitted.batchInfo())

    def onBatchStarted(self, batchStarted):
        self.batchInfosStarted.append(batchStarted.batchInfo())

    def onBatchCompleted(self, batchCompleted):
        self.batchInfosCompleted.append(batchCompleted.batchInfo())
        '''
        batchDate = datetime.datetime.fromtimestamp(
            self.batchInfosCompleted[len(self.batchInfosCompleted)-1]
            .outputOperationInfos()[len(self.batchInfosCompleted)-1]
            .endTime() / 1000)
        logger.warning('batchDate: ' + str(batchDate))
        if batchDate - last_updated > datetime.timedelta(minutes=1):
            logger.warning('Date has changed, Stopping StreamingContext.')
            StreamingContext.getActive().stop(stopSparkContext=False, stopGraceFully=True)
        '''
        batchDate = None
        batchinfo = self.batchInfosCompleted[-1]
        for outputId in batchinfo.outputOperationInfos():
            outputInfo = batchinfo.outputOperationInfos()[outputId]
            batchDate = datetime.datetime.fromtimestamp(outputInfo.endTime()/1000)

        logger.warning('batch date: %s' % batchDate)
        if batchDate - last_updated > datetime.timedelta(minutes=1):
            logger.warning('Date has changed, Stopping StreamingContext.')
            StreamingContext.getActive().stop(stopSparkContext=False, stopGraceFully=True)

def getSqlContextInstance():
    if ('sparkSession' not in globals()):
        globals()['sparkSession'] = SparkSession \
            .builder \
            .appName("BDSA v0.1 alpha") \
            .enableHiveSupport() \
            .getOrCreate()
    return globals()['sparkSession']


def parse(line):
    if '-fw' in line:
        return logParser.parseIPTables(line)
    elif '-net-bc' in line:
        return logParser.parseBCAccessLog(line)
    else:
        return line


def save(rdd, type):
    spark = getSqlContextInstance()
    if rdd.isEmpty():
        logger.warning('Empty RDD. Skipping.')
    else:
        df = spark.createDataFrame(rdd)
        logger.warning("Saving DataFrame - %s." % type)
        df.write.saveAsTable('dw_srm.%s' % type, format='parquet', mode='append', partitionBy='date')


def save_fw(rdd):
    save(rdd, 'fw')


def save_proxy(rdd):
    save(rdd, 'proxysg')


def process_fw(time, rdd):
    if not rdd.isEmpty():
        output_rdd = rdd.filter(lambda x: '-fw' in x) \
            .map(parse) \
            .filter(lambda x: isinstance(x, Row)).repartition(2)
        return output_rdd


# https://issues.apache.org/jira/browse/PARQUET-222 - Parquet writer memory allocation
def process_proxy(time, rdd):
    if not rdd.isEmpty():
        output_rdd = rdd.filter(lambda x: '-net-bc' in x) \
            .map(parse) \
            .filter(lambda x: isinstance(x, Row)).repartition(2)
        return output_rdd


'''Main function'''
if __name__ == '__main__':
    appConfig = conf.Config(exec_cores=4, yarn_cores=8, cores_max=8, instances=2, queue='root.llama')
    logParser = Parser()

    # Create SparkContext and StreamingListener
    sc = SparkContext(conf=appConfig.setSparkConf())

    while True:
        if StreamingContext.getActive() is None:
            # Create streaming Context and DStreams
            logger.warning('Starting streaming context.')
            ssc = StreamingContext(sc, 120)
            collector = batchInfoCollector()
            ssc.addStreamingListener(collector)
            last_updated = datetime.datetime.today()
            logger.warning('last_updated: ' + str(last_updated))
            stream = ssc.textFileStream(
                '/data/datalake/dbs/dl_raw_infra.db/syslog_log/dt=%s' % last_updated.strftime("%Y%m%d"))
            logger.warning('setting new path: /data/datalake/dbs/dl_raw_infra.db/syslog_log/dt=%s' % last_updated.strftime("%Y%m%d"))
            fwDStream = stream.transform(process_fw)
            proxyStream = stream.transform(process_proxy)
            fwDStream.foreachRDD(save_fw)
            proxyStream.foreachRDD(save_proxy)

            # Start Streaming Context and wait for termination
            ssc.start()
            ssc.awaitTermination()
