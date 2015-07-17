import urllib2

import lib.parser as parser
from pyspark.sql import SQLContext
from pyspark.sql.types import *


def update_alienvault_otx(sContext):
    sqlCtx = SQLContext(sContext)
    data = urllib2.urlopen('http://reputation.alienvault.com/reputation.data')
    results = []
    for line in data:
        results.append(line)

    rdd = sContext.parallelize(results)
    parsed_rdd = rdd.map(parser.Parser.parseAlienVaultOTX)
    parsed_rdd.collect()
    df = parsed_rdd.toDF()
    df.save('reputation/otx', 'parquet', 'overwrite')