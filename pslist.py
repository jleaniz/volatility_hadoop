import utils
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *

if __name__ == '__main__':
    sc = SparkContext("local", "SparkVolatility", pyFiles=['utils.py','hdfs.py','parser.py'])
    volatility = utils.SparkVolatility('pslist')
    sqlContext = SQLContext(sc)

    df = sqlContext.load('Volatility/imageinfo')
    sqlContext.registerDataFrameAsTable(df, "imageinfo")
    imginfo = sqlContext.sql("SELECT * FROM imageinfo") 

    pslist = imginfo.map(volatility.Execute)
    pslist.cache()

    df = pslist.toDF()

    df.save('Volatility/pslist', 'parquet', 'append')

    sc.stop()
    