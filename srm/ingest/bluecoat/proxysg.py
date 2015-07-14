import srm.lib.parser as parser
import os
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

def save_access_log(sContext):
	#alter table sg_accesslog add partition (p_year='2015', p_month='07', p_day='02');
	#load data inpath '/user/cloudera/proxy/sg_accesslog_p/p_year=2015/p_month=07/p_day=02' into table sg_accesslog partition (p_year='2015', p_month='07', p_day='02');
	sqlCtx = SQLContext(sContext)
	sqlCtx.setConf('spark.sql.parquet.compression.codec', 'snappy')
	days = os.listdir('/mnt/hdfs/user/cloudera/proxy/raw/2015/06')
	for day in days:
		access_log_rdd = sContext.textFile('/user/cloudera/proxy/raw/2015/06/' + day + '/*.log')
		parsed_rdd = access_log_rdd.mapPartitions(parser.parseBCAccessLog)
		df = parsed_rdd.toDF()
		df.save('/user/cloudera/proxy/accesslog/p_year=2015/p_month=06/' + 'p_day=' + day, 'parquet', 'append')
