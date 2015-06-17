from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':
	sc = SparkContext("local[8]", "SparkVolatility", pyFiles=['parser.py'])
	sqlContext = SQLContext(sc)

	df = sqlContext.load('BlueCoat/accessLog')
	sqlContext.registerDataFrameAsTable(df, "accesslog")
	data = sqlContext.sql("SELECT host, count(*) as hits FROM accesslog WHERE action LIKE '%DENIED%' GROUP BY host ORDER BY hits DESC") 
	data.cache()
	data.show()
	sc.stop()
    