from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':
    sc = SparkContext("local[8]", "SparkVolatility", pyFiles=['parser.py'])
    sqlContext = SQLContext(sc)

    df = sqlContext.load('fw/log')
    sqlContext.registerDataFrameAsTable(df, "fwlog")
    data = sqlContext.sql(
        "SELECT dstip, count(*) as hits FROM fwlog WHERE action LIKE 'DENY' GROUP BY dstip ORDER BY hits DESC")
    data.cache()
    data.show()
    sc.stop()
