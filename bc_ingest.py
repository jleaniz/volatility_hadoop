import parser
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':

	sc = SparkContext("local[8]", "SparkVolatility", pyFiles=['parser.py'])

	sqlCtx = SQLContext(sc)
	access_log_rdd = sc.textFile('/user/cloudera/BlueCoat/raw', 24)

#	parsed_rdd = access_log_rdd.filter(lambda line: 'accelerated_pac_base' not in line) \
#								.filter(lambda line: 'databssint' not in line) \
#								.map(parser.parseBCAccessLog)
	parsed_rdd = access_log_rdd.mapPartitions(parser.parseBCAccessLog)

	df = parsed_rdd.toDF()
	df.save('BlueCoat/accessLog', 'parquet', 'append')
#	df.show(100)

	sc.stop()
