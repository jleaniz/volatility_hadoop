from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':
sc = SparkContext("local[8]", "SparkVolatility")
sqlctx = SQLContext(sc)
df = sqlctx.load('BlueCoat/accessLog')
sqlctx.registerDataFrameAsTable(df, 'bluecoat')
df2 = sqlctx.load('reputation/c2')
sqlctx.registerDataFrameAsTable(df2, 'c2')
df3 = sqlctx.load('fw/log')
sqlctx.registerDataFrameAsTable(df3, 'fw')
test = sqlctx.sql('SELECT srcip, dstip, dstport, action, count(*) as hits FROM fw WHERE action LIKE "%DENY%" AND dstport LIKE "3389" GROUP BY srcip, dstip, dstport, action ORDER BY hits DESC')
test.cache()
for i in test.take(100):
	print i