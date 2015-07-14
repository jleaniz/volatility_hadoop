from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':
	SparkContext.setSystemProperty('spark.executor.memory', '2g')
	sc = SparkContext("local[8]", "SparkVolatility", pyFiles=['parser.py'])
	sqlContext = SQLContext(sc)

	df = sqlContext.load('impala_tables/bluecoat')
	sqlContext.registerDataFrameAsTable(df, "accesslog")
	data = sqlContext.sql("SELECT host, count(*) as hits FROM accesslog WHERE action LIKE '%DENIED%' GROUP BY host ORDER BY hits DESC") 
	data.show()
	sc.stop()
