import lib.utils as utils
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

def save_imageinfo(sContext):
    sqlContext = SQLContext(sContext)
    images = sContext.textFile('/user/cloudera/imgnames.txt')
    volatility = utils.SparkVolatility('imageinfo')
    rdd = images.map(volatility.Execute)
    rdd.cache()
    df = rdd.toDF()
    df.save('Volatility/imageinfo', 'parquet', 'append')
