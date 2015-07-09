import srm.lib.parser as parser
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

def save_access_log(sContext):
	sqlCtx = SQLContext(sContext)
	sqlCtx.setConf('spark.sql.parquet.compression.codec', 'gzip')
	access_log_rdd = sContext.textFile('/user/cloudera/BlueCoat/raw', 24)
	parsed_rdd = access_log_rdd.mapPartitions(parser.parseBCAccessLog)
	df = parsed_rdd.toDF()
	df.save('/user/cloudera/BlueCoat/accessLog', 'parquet', 'append')
