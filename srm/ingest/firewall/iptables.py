import srm.lib.parser as parser
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

def save_log(sContext):
	sqlCtx = SQLContext(sContext)
	sqlCtx.setConf('spark.sql.parquet.compression.codec', 'snappy')
	access_log_rdd = sContext.textFile('/user/cloudera/2015/*/*')
	parsed_rdd = access_log_rdd.mapPartitions(parser.parseIPTables)
	df = parsed_rdd.toDF()
	df.save('fw/log', 'parquet', 'append')
