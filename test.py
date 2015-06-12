from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':
    sc = SparkContext("local", "SparkVolatility", pyFiles=['utils.py','hdfs.py','parser.py'])
    sqlContext = SQLContext(sc)
    df = sqlContext.load('Volatility/imageinfo')
    df.show()
    sc.stop()