import srm.lib.utils as utils
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql.types import *


def save_pslist(sContext):
    volatility = utils.SparkVolatility('pslist')
    sqlContext = SQLContext(sContext)
    df = sqlContext.load('Volatility/imageinfo')
    sqlContext.registerDataFrameAsTable(df, "imageinfo")
    imginfo = sqlContext.sql("SELECT * FROM imageinfo")
    pslist = imginfo.map(volatility.Execute)
    pslist.cache()
    df = pslist.toDF()
    df.save('Volatility/pslist', 'parquet', 'append')
