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
    path = '/mnt/hdfs/user/cloudera/proxy/raw/'
	months = os.listdir(path + host+'/2015/')
    
    for month in months:
        days = os.listdir(path + host+'/2015/' + month)
        for day in days:
            if os.listdir(path + host+'/2015/' + month + '/' + day):
                access_log_rdd = sContext.textFile('/user/cloudera/proxy/raw/'+host+'/2015/' 
                	+ month + '/' + day + '/*').repartition(sContext.defaultParallelism)
                parsed_rdd = access_log_rdd.mapPartitions(parser.parseIPTables)
                df = parsed_rdd.toDF()
                df.save('/user/cloudera/proxy/accesslog/p_year=2015/p_month=' + str(int(month)) 
                	+ '/p_day=' + str(int(day)), 'parquet', 'append')

