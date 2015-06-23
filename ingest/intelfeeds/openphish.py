import urllib2
import lib.parser as parser
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

def update_openphish(sContext):
	sqlCtx = SQLContext(sContext)
	data = urllib2.urlopen('https://openphish.com/feed.txt')
	results = []
	for line in data:
		results.append(line)

	rdd = sContext.parallelize(results)
	parsed_rdd = rdd.map(parser.parseOpenPhish)
	parsed_rdd.collect()
	df = parsed_rdd.toDF()
	df.save('reputation/openphish', 'parquet', 'overwrite')