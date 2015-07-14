import os
import srm.lib.parser as parser
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

def save_log(sContext, host):
    sqlCtx = SQLContext(sContext)
    sqlCtx.setConf('spark.sql.parquet.compression.codec', 'snappy')
    path = '/mnt/hdfs/user/cloudera/fw/raw/'
    months = os.listdir(path + host +'/2015/')
    for month in months:
        days = os.listdir(path + host +'/2015/' + month)
        for day in days:
            if os.listdir(path + host +'/2015/' + month + '/' + day):
                access_log_rdd = sContext.textFile('/user/cloudera/fw/raw/'+host+'/2015/' 
                    + month + '/' + day + '/*').repartition(sContext.defaultParallelism)
                parsed_rdd = access_log_rdd.mapPartitions(parser.parseIPTables)
                df = parsed_rdd.toDF()
                if 'onl' in host:
	                df.save('/user/cloudera/fw/onl/year=2015/month=' + str(int(month)) 
                        + '/day=' + str(int(day)), 'parquet', 'append')
                else:
                    df.save('/user/cloudera/fw/corp/year=2015/month=' + str(int(month)) 
                        + '/day=' + str(int(day)), 'parquet', 'append')
