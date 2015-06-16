import utils
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':

    sc = SparkContext("local", "SparkVolatility", pyFiles=['utils.py','hdfs.py','parser.py'])
    sqlContext = SQLContext(sc)
    images = sc.textFile('/user/cloudera/imgnames.txt')

    volatility = utils.SparkVolatility('imageinfo')

    rdd = images.map(volatility.Execute)
    rdd.cache()

    df = rdd.toDF()

    df.save('Volatility/imageinfo', 'parquet', 'append')

    sc.stop()