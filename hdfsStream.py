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
from pyspark.streaming import StreamingContext
from pyspark.sql import SQLContext
from pyspark.sql.types import Row
from pyspark import SparkContext
from pyspark import StorageLevel
from lib.parser import Parser
from config import config as conf
import logging


logging.basicConfig(level=logging.WARN)
logger = logging.getLogger(__name__)


def getSqlContextInstance(sparkContext):
    if ('sqlContextSingletonInstance' not in globals()):
        globals()['sqlContextSingletonInstance'] = SQLContext(sparkContext)
    return globals()['sqlContextSingletonInstance']


def parse(line):
    if '-fw' in line:
        return logParser.parseIPTables(line)
    elif '-net-bc' in line:
        return logParser.parseBCAccessLogIter(line)
    else:
        return line


def save(rdd, type):
    sqlContext = getSqlContextInstance(rdd.context)
    sqlContext.setConf('spark.sql.parquet.compression.codec', 'snappy')
    if rdd.isEmpty():
        logger.warning('Empty RDD. Skipping.')
    else:
        df = sqlContext.createDataFrame(rdd)
        logger.warning("Saving DataFrame - %s." % (type))
        #df.coalesce(1).write.parquet('/user/jleaniz/%s' % (type), mode="append", partitionBy=('date'))
        df.coalesce(1).write.saveAsTable('dw_srm.fw', format='parquet', mode='append', partitionBy='date')

def save_fw(rdd):
    save(rdd, 'fw')


def save_proxy(rdd):
    save(rdd, 'proxysg')

def process_fw(time, rdd):
    if not rdd.isEmpty():
        output_rdd = rdd.filter(lambda x: '-fw' in x)\
            #.map(parse) \
            #.filter(lambda x: isinstance(x, Row))
        print output_rdd.first()
        return output_rdd


#https://issues.apache.org/jira/browse/PARQUET-222 - Parquet writer memory allocation
def process_proxy(time, rdd):
    output_rdd = rdd.map(lambda x: str(time) + ' ' + x[0]['host'] + ' ' + x[1]) \
        .filter(lambda x: '-net-bc' in x).map(parse) \
        .filter(lambda x: isinstance(x, Row)).repartition(10)
    return output_rdd


'''Main function'''
if __name__ == '__main__':
    appConfig = conf.Config()
    sc = SparkContext(conf=appConfig.setSparkConf())
    ssc = StreamingContext(sc, 30)
    logParser = Parser(type='iptables')

    stream = ssc.textFileStream('/data/datalake/dbs/dl_raw_infra.db/syslog_log/dt=20161017')
    #stream.pprint()

    fwDStream = stream.transform(process_fw)
    fwDStream.pprint()
    fwDStream.foreachRDD(save_fw)

    ssc.start()
    ssc.awaitTermination()