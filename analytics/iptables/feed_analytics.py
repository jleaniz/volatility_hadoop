from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':
	sc = SparkContext("local[8]", "SparkVolatility")
	sqlctx = SQLContext(sc)
	df = sqlctx.load('BlueCoat/accessLog')
	sqlctx.registerDataFrameAsTable(df, 'bluecoat')
	df2 = sqlctx.load('reputation/alienvault')
	sqlctx.registerDataFrameAsTable(df2, 'alienvault')
	test = sqlctx.sql('select clientip, host, query, username, categories from bluecoat join alienvault on bluecoat.host=alienvault.ip')
	test.cache()
	r = test.distinct()
	r.cache()
	for i in r.collect():
		print i