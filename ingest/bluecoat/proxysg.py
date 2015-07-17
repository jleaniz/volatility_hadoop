import os

import bdsa.lib.parser as parser
from pyspark.sql import SQLContext
from pyspark.sql.types import *


def save_access_log(sContext, path):
    sqlCtx = SQLContext(sContext)
    sqlCtx.setConf('spark.sql.parquet.compression.codec', 'snappy')
    local_path = '/mnt/hdfs/' + path
    years = os.listdir(local_path)
    for year in years:
        months = os.listdir(local_path + '/' + year)
        for month in months:
            days = os.listdir(local_path + '/' + year + '/' + month)
            for day in days:
                if os.listdir(local_path + '/' + year + '/' + month + '/' + day):
                    access_log_rdd = sContext.textFile(path + '/' + year + '/'
                                                       + month + '/' + day + '/*').repartition(
                        sContext.defaultParallelism)
                    parsed_rdd = access_log_rdd.mapPartitions(parser.Parser.parseBCAccessLog)
                    df = parsed_rdd.toDF()
                    df.save('/user/cloudera/proxy/accesslog/p_year=2015/p_month=' + str(int(month))
                            + '/p_day=' + str(int(day)), 'parquet', 'append')
